#!/bin/bash 
#Author Graziano Marallo
echo "+++ Backing up Thesis +++"
echo ""
echo "+++ Removing old files +++"
echo "James1308" | sudo -S  rm -r /path/to/folder
if [ $? -eq 0 ]; then
     echo  "*** Old files removed correctly ***" 
else
     echo   "XXX Error XXX"
fi
echo ""


echo "*** Backup on Git runnig... ***"
echo ""
git add .
git commit -m "get message from command line"
git push -u origin master
echo ""
if [ $? -eq 0 ]; then
    echo  "*** All done! Git repo updated ***" 
 else
    echo "XXX Git repo  backup failed XXX"
fi
