#!/bin/false

indent_multiline() {
	cat << EOF | sed 's/^/   /'
$*
EOF
}

tap13() {
	local rc idx text log

	rc="$1"
	idx="$2"
	text="$3"
	log="$4"

	case ${rc} in
	0)
		echo "ok ${idx} - ${text}"
		if [ ${V} -eq 1 ]; then
			echo " ---"
			echo " rc: ${rc}"
			echo " log: |"
			indent_multiline "${log}"
			echo " ..."
		fi
		;;
	77)
		echo "ok ${idx} - ${text} # SKIP"
		;;
	*)
		echo "not ok ${idx} - ${text}"
		echo " ---"
		echo " rc: ${rc}"
		echo " log: |"
		indent_multiline "${log}"
		echo "  ..."
		;;
	esac

	return 0
}
