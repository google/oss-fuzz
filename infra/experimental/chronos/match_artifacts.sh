#/bin/bash -eux

CMP1=$1
CMP2=$2

for exec1 in $(find $CMP1/ -type f -executable); do
  base=$(basename $exec1)

  exec2=$CMP2/${base}
  if [ ! -f ${exec2} ]; then
    exit 1
  fi

  comparison=$(cmp --silent $exec1 $exec2; echo $?)
  if [[ $comparison -ne 0 ]]; then
    exit 1
  fi
done

exit 0
