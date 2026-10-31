- An agent message's `hop` is at least one more than the last message
  that triggered its instance since the last `control.resume`, whatever
  `reply_to` names. Two agents that kept naming a human's message (hop 0)
  sent hop 1 forever and never reached `loop_guard.max_agent_turns`
  (SR-33).
