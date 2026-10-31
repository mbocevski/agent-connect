- The reconnect drain's exemption from the per-minute rates is bounded per
  identity across connections: twice its per-sender rate in any hour,
  however often the relay reconnects. Before, each connection renewed it,
  and the relay decides when a drain starts and ends, so a relay colluding
  with a member could bypass the SPEC §10.2 rates (SR-36).
