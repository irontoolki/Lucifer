read -p "[!] Delete Database; Are you sure[Y/y]? " -n 1 -r
echo    # (optional) move to a new line
if [[  $REPLY =~ ^[Yy]$ ]]
then
	mysql -u root -p1qaz\!QAZ -e "use icap; DELETE FROM lucifer WHERE 1;" 
fi
