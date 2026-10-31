- In `free` and `moderated` mode an instance is no longer triggered by a
  message from another instance of its own identity (a replica's), which it
  gets as context (in `free` mode, unless the message names the identity in
  `addressee`): SPEC §9.3 triggers all members except the sender, and a
  member is an identity. Two replicas of the moderator or the floor holder
  can no longer answer each other until the loop guard stops them (SR-35).
