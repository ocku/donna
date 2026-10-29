-- Two explicit Redis keys: per-entry HASH and provider-owned FIFO ZSET.
-- Side-effect-free; expiry/access never silently changes a read generation.
-- Envelope/population limits mirror redis_engine_codec.rs and the apply script.
-- EVAL scripts remain independently executable; revisions fit Lua's exact integers.
local MAX_REVISION = 9007199254740991
local MAX_REVISION_DIGITS = 16
local MAX_ENTRY_BYTES = 1024 * 1024
local MAX_FAMILY_MEMBERS = 256

local rev = redis.call('HGET', KEYS[1], 'revision')
if not rev then
  if redis.call('HLEN', KEYS[1]) ~= 0 or redis.call('ZCARD', KEYS[2]) ~= 0 then
    return redis.error_reply('inconsistent provider namespace')
  end
  rev = '0'
end
if not string.match(rev, '^%d+$') or #rev > MAX_REVISION_DIGITS or
   (#rev > 1 and string.sub(rev, 1, 1) == '0') or tonumber(rev) > MAX_REVISION then
  return redis.error_reply('invalid provider revision')
end
if ARGV[1] ~= '' and ARGV[1] ~= rev then
  return {0, rev, {}}
end

local max_entries, max_bytes = tonumber(ARGV[2]), tonumber(ARGV[3])
local rows, seen, bytes = {}, {}, 0

local function add(field, required)
  if seen[field] then
    return
  end

  if redis.call('HEXISTS', KEYS[1], field) == 0 then
    if required then
      error('dangling family member')
    end
    return
  end

  local size = redis.call('HSTRLEN', KEYS[1], field)
  local accounted = size + #field
  if size > MAX_ENTRY_BYTES or #rows + 1 > max_entries or bytes + accounted > max_bytes then
    error('provider read exceeds caller bounds')
  end
  bytes = bytes + accounted
  seen[field] = true
  rows[#rows + 1] = {field, redis.call('HGET', KEYS[1], field)}
end

local at = 5
for i = 1, tonumber(ARGV[4]) do
  add(ARGV[at], false)
  at = at + 1
end

local families = tonumber(ARGV[at])
at = at + 1

for i = 1, families do
  local field = ARGV[at]
  at = at + 1

  if redis.call('HSTRLEN', KEYS[1], field) > MAX_ENTRY_BYTES then
    return redis.error_reply('oversized family index')
  end
  local value = redis.call('HGET', KEYS[1], field) or ''
  local count = 0
  for entry in string.gmatch(value, '[^|]+') do
    count = count + 1
    if count > MAX_FAMILY_MEMBERS or not string.match(entry, '^e:[0-9a-f]+$') then
      return redis.error_reply('invalid family index')
    end
    add(entry, true)
  end
end

return {1, rev, rows}
