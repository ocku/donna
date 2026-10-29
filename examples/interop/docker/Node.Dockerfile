FROM node:24-bookworm-slim

WORKDIR /suite
COPY examples/interop/node/client.mjs examples/interop/node/recursive.mjs ./

CMD ["node", "client.mjs"]
