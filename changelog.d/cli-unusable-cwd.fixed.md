- On macOS, `sudo -u _agentconnect agentconnect ...` from a directory that user
  can't search no longer fails with a Python traceback before it reads its
  arguments. The command runs from `/` there, and refuses a relative path, since
  it couldn't mean what you typed.
