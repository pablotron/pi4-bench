#!/bin/sh

for i in v4.wg flex cherry zero pecan peach pmdn.org; do
  echo $i
  mkdir -p $i
  ssh $i lscpu > $i/lscpu.txt
  ssh $i openssl speed -mr -evp blake2b512 sha256 sha512 aes > $i/openssl-speed.txt &
done

# join tasks
fg

# mask hostnames
mv v4.wg v4
mv pmdn.org linode

# generate csvs in csvs/
ruby ./gen-csvs.rb */openssl-speed.txt

# generate charts in svgs/
for i in csvs/*.csv; do
  python3 ./plot.py "$i" "${i//csv/svg}"
done

echo done
