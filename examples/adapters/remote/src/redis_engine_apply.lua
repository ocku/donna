-- Preflight a metadata journal before writes: Lua errors do not roll back writes.
-- Envelope/population limits mirror redis_engine_codec.rs and the read script.
-- EVAL scripts remain independently executable; revisions fit Lua's exact integers.
local MAX_REVISION = 9007199254740991
local MAX_REVISION_DIGITS = 16
local MAX_COUNTER_DIGITS = 8
local MAX_ENTRY_BYTES = 1024 * 1024
local MAX_ENTRIES = 4096
local MAX_FAMILY_MEMBERS = 256
local MAX_INDEX_BYTES = 1550

local rev = redis.call('HGET', KEYS[1], 'revision')
if not rev then
  if redis.call('HLEN', KEYS[1]) ~= 0 or redis.call('ZCARD', KEYS[2]) ~= 0 then
    return redis.error_reply('inconsistent provider namespace')
  end
  rev = '0'
end
if not string.match(rev, '^%d+$') or #rev > MAX_REVISION_DIGITS or
   (#rev > 1 and string.sub(rev, 1, 1) == '0') or tonumber(rev) >= MAX_REVISION then
  return redis.error_reply('invalid or exhausted provider revision')
end
if rev ~= ARGV[1] then
  return {0, rev, 0, 0}
end

local capacity, bytecap = tonumber(ARGV[2]), tonumber(ARGV[3])
local used = redis.call('HGET', KEYS[1], 'bytes') or '0'
if #used > MAX_COUNTER_DIGITS or not string.match(used, '^%d+$') or
   tonumber(used) > bytecap or (#used > 1 and string.sub(used, 1, 1) == '0') then
  return redis.error_reply('invalid provider byte counter')
end
used = tonumber(used)

local count = redis.call('ZCARD', KEYS[2])
if count > MAX_ENTRIES then
  return redis.error_reply('provider population exceeds bound')
end

local staged, families, incoming = {}, {}, {}
local evicted, declined = 0, 0

local function members(family)
  if families[family] then
    return families[family]
  end
  if redis.call('HSTRLEN', KEYS[1], family) > MAX_ENTRY_BYTES then
    error('oversized family index')
  end

  local result, n = {}, 0
  for field in string.gmatch(redis.call('HGET', KEYS[1], family) or '', '[^|]+') do
    n = n + 1
    if n > MAX_FAMILY_MEMBERS or result[field] or not string.match(field, '^e:[0-9a-f]+$') then
      error('invalid family index')
    end
    result[field] = true
  end
  families[family] = result
  return result
end

local function load(field, family)
  local slot = staged[field]
  if slot then
    if family and slot.family ~= family then
      error('changed entry family')
    end
    return slot
  end

  local exists = redis.call('HEXISTS', KEYS[1], field) == 1
  local stored = redis.call('HGET', KEYS[1], 'm:' .. field)
  if exists ~= (stored ~= false) then
    error('entry metadata mismatch')
  end
  if stored and family and stored ~= family then
    error('changed entry family')
  end
  family = stored or family
  if not family then
    error('missing entry family')
  end

  local set = members(family)
  if exists ~= (set[field] == true) or exists ~= (redis.call('ZSCORE', KEYS[2], field) ~= false) then
    error('entry index mismatch')
  end

  local size = redis.call('HSTRLEN', KEYS[1], field)
  if size > MAX_ENTRY_BYTES or exists and size == 0 then
    error('invalid entry size')
  end
  slot = {family = family, size = size, present = exists, value = nil, touched = false}
  staged[field] = slot
  return slot
end

local function remove(field, family)
  local slot = load(field, family)
  if slot.present then
    count = count - 1
    used = used - slot.size
    members(slot.family)[field] = nil
  end
  slot.present = false
  slot.size = 0
  slot.value = false
  slot.touched = true
end

local at = 5
for i = 1, tonumber(ARGV[4]) do
  local op, field, family, value = ARGV[at], ARGV[at + 1], ARGV[at + 2], ARGV[at + 3]
  at = at + 4
  if not field or not family or not value or #field > MAX_INDEX_BYTES or
     not string.match(field, '^e:[0-9a-f]+$') or #family > MAX_INDEX_BYTES or
     not string.match(family, '^f:[0-9a-f]+$') then
    error('invalid mutation index')
  end

  if op == 'P' then
    if #value > MAX_ENTRY_BYTES then
      error('oversized mutation payload')
    end
    remove(field, family)
    local set = members(family)
    local n = 0
    for _ in pairs(set) do
      n = n + 1
    end

    if #value <= bytecap and n < MAX_FAMILY_MEMBERS then
      local slot = staged[field]
      slot.present = true
      slot.size = #value
      slot.value = value
      set[field] = true
      used = used + #value
      count = count + 1
      incoming[#incoming + 1] = field
    else
      declined = declined + 1
    end
  elseif op == 'R' then
    remove(field, family)
  elseif op ~= 'A' then
    error('invalid provider mutation')
  end
end

if used < 0 or count < 0 then
  error('invalid provider counters')
end
if count > capacity or used > bytecap then
  local oldest = redis.call('ZRANGE', KEYS[2], 0, -1)
  for _, field in ipairs(incoming) do
    oldest[#oldest + 1] = field
  end
  for _, field in ipairs(oldest) do
    if count <= capacity and used <= bytecap then
      break
    end
    local slot = staged[field]
    -- Existing replacements have become fresh admissions; consider them later.
    if not slot or slot.present and slot.value == nil then
      remove(field, nil)
      evicted = evicted + 1
    end
  end
  for _, field in ipairs(incoming) do
    if count <= capacity and used <= bytecap then
      break
    end
    if staged[field].present then
      remove(field, nil)
      evicted = evicted + 1
    end
  end
end
if count > capacity or used > bytecap then
  error('provider retention planning failed')
end

local indexes = {}
for family, set in pairs(families) do
  local fields = {}
  for field in pairs(set) do
    fields[#fields + 1] = field
  end
  table.sort(fields)
  indexes[family] = table.concat(fields, '|')
end
local nextrev = string.format('%.0f', tonumber(rev) + 1)

-- No validation/error callbacks after this point; namespace keys are exclusively
-- owned by this adapter and the lab reserves memory beyond its hard data budget.
redis.call('HSET', KEYS[1], 'revision', nextrev, 'bytes', string.format('%.0f', used))
for field, slot in pairs(staged) do
  if slot.touched then
    if slot.present then
      redis.call('HSET', KEYS[1], field, slot.value, 'm:' .. field, slot.family)
      redis.call('ZADD', KEYS[2], nextrev, field)
    else
      redis.call('HDEL', KEYS[1], field, 'm:' .. field)
      redis.call('ZREM', KEYS[2], field)
    end
  end
end
for family, value in pairs(indexes) do
  if value == '' then
    redis.call('HDEL', KEYS[1], family)
  else
    redis.call('HSET', KEYS[1], family, value)
  end
end

return {1, nextrev, evicted, declined}
