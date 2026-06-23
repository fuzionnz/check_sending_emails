#! /bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR"
if [[ ! -f "check_sending_emails.sh" ]] ; then
	echo "Failed to find script"
	exit 1;
fi
echo "Running"
pipenv run python check_sending_emails.py
