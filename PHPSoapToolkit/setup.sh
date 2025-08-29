export KEY_ALIAS="tuctest-cert01.2025-08-27"
export KEY_FILE="tuctest-cert01.2025-08-27.p12"
export KEY_DIRECTORY="cert01"
if [ -z "$KEY_PASS" ] ; then
	echo "enter KEY PASSPHRASE:"
	read -s KEY_PASS && export KEY_PASS
fi

