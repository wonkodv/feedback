#!/bin/sh

set -e
 
sigint_handler()
{
  kill $PID
  exit
}

trap sigint_handler SIGINT

while true; do
    set -e
    target/debug/feedback &
    PID=$!
    inotifywait target/debug/feedback
    kill $PID
done

