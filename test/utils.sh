#!/bin/false

tap13() {
	local rc="$1"
	local idx="$2"
	local text="$3"
	local log="$4"

	case ${rc} in
	0)
		echo "ok ${idx} - ${text}"
		if [ ${V} -eq 1 ]; then
			echo " ---"
			echo "${log}"
			echo " ---"
		fi
		;;
	77)
		echo "ok ${idx} # SKIP"
		;;
	*)
		echo "not ok ${idx} - ${text}"
		echo " ---"
		echo "${log}"
		echo " ---"
		;;
	esac

	return 0
}
