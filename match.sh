rm -R UPLOAD
mkdir UPLOAD
echo "Start..."
grep -rl "Content-Disposition:" /var/tmp > find.log
while read p; do
	echo "File Found -> "$p
	strings $p | grep "Content-Type"
	ScanFname=` strings $p | grep "filename" | awk '{print $4}'| sed -e 's/filename="\(.*\)"/\1/'`
	echo $p" --> UPLOAD/"$ScanFname 	
	## check for any overwrite...
	ScanFinalName=$RANDOM-$ScanFname
	cp  $p UPLOAD/$ScanFinalName
	echo "x=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=x"
done <find.log
echo "Copying Done, Press Key..."
#read Press
echo "--------------------------------------------------------------------------"
ls -ltr --block-size=M UPLOAD
