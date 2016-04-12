# Copyright (C) 2015-2016 Myriam Leggieri <iammyr@email.com>
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.

#!/bin/bash

ERROR_ARGS="Error: Argument/s not provided."
USAGE="Usage: $0 <web app URL> <file listing web app URL suffix to attack> <directory with .pay files containing one malicious payload per line>. Check errors.log for errors."
# App response indicating that an attack was detected and blocked
DENIED_MESSAGE="Error processing request."
ERROR_INVALID="Error: Invalid argument/s provided."
ERROR_INVALID_CODE=2


check_existence(){
   if [[ -z $1 ]] || [[ -z $2 ]] || [[ -z $3 ]]
   then
     echo $ERROR_ARGS
     echo $USAGE
     exit $ERROR_INVALID_CODE
   fi
   return $TRUE
}

check_validity(){
   if [[ $1 != http://* ]] || [[ ! -r $2 ]] || [[ ! -d $3 ]]
   then
     echo $ERROR_INVALID
     echo $USAGE
     exit $ERROR_INVALID_CODE
   fi
   return $TRUE    
}

check_args(){
   check_existence $1 $2 $3
   check_validity $1 $2 $3
   return $TRUE
}

init_file(){
   if [[ -r $4 ]]; then
     rm $4
   fi
}


#Log eventual errors returned by curl.
error_check(){
   if [[ $1 == Error* ]]; then
      echo "Error: curl for line $2 in file $3 was not executed." >> errors.log
   fi
}


#Check whether the attack attempt was successfully blocked or not.
is_success(){
   if [[ $1 == $DENIED_MESSAGE ]]; then
	isSuccess=1
   else
	isSuccess=0
   fi
}


#Submit an attack by including the malicious payload simply as a POST parameter value.
attack_param_value(){
   #echo "Submitting payload $1 from file $2"
   payload="vector=$1"
   status=$(curl -X POST -d "$payload" $3/$4)
   is_success "$status"   
   if [ $isSuccess -eq 0 ]; then
   	error_check $status $1 $2
   fi
}


#Submit an attack by including the malicious payload as an argument for a call to a stored procedure (within a POST parameter value)
attack_stored_procedure(){
   #echo "Submitting payload $1 from file $2 (attacking stored procedures)"
   #escape apostrophes by doubling them (as required by stored procedures to succeed)
   content=cat $1 | sed 's/'"'"'/'"'"''"'"'/g'
   payload="vector='verifyUserPassword(foo,$content)'"
   status=$(curl -X POST -d "$payload" $3/$4)
   is_success "$status"
   if [ $isSuccess -eq 0 ]; then
        error_check $status $1 $2
   fi
}


#Submit an attack by including the malicious payload as the value of a request header.
attack_header(){
   #echo "Submitting attack vector $1 from file $2 inside the request header"
   payload="vector: $1"
   status=$(curl -X POST -H "$payload" $3/$4)
   is_success "$status"
   if [ $isSuccess -eq 0 ]; then
        error_check $status $1 $2
   fi
}

#Submit an attack by including the malicious payload as a POST parameter's name.
attack_param_name(){
  # echo "Submitting attack vector $1 from file $2 as the payload parameter's name"
   payload="$1=vector"
   status=$(curl -X POST -H "$payload" $3/$4)
   is_success "$status"
   if [ $isSuccess -eq 0 ]; then
        error_check $status $1 $2
   fi
}


#Submit an attack by including the malicious payload as a cookie value.
attack_cookie(){
 #  echo "Submitting attack vector $1 from file $2 as cookie"
   payload="vector=$1"
   status=$(curl --cookie "$payload" $3/$4)
   is_success "$status"
   if [ $isSuccess -eq 0 ]; then
        error_check $status $1 $2
   fi
}


#Submit a series of attacks for each vulnerable application page found in the list provided.
attack(){
   path="$3/*"
   echo "path $path"
   for testcase in $(cat $2); do
      isSuccess=0
      if [ $isSuccess -eq 0 ]; then
	echo "alright"
      else
	echo "dho"
      fi
      for file in $path; do
         if [[ $file == *.pay ]] && [ $isSuccess -eq 0 ]; then
            echo "Reading from file $file"
            while IFS='' read -r line || [[ -n "$line" ]] && [ $isSuccess -eq 0 ]; do
               line=$( echo $line | sed s/\"/\\\"/g ) 
		echo "line=$line"
		echo "file=$file"
		echo "1=$1"
		echo "testcase=$testcase"
                attack_param_value "$line" "$file" "$1" "$testcase"
	       if [ $isSuccess -eq 0 ]; then
		       attack_stored_procedure "$line" "$file" "$1" "$testcase"
	       fi
               if [ $isSuccess -eq 0 ]; then
	               attack_header "$line" "$file" "$1" "$testcase"
               fi
	       if [ $isSuccess -eq 0 ]; then
	               attack_param_name "$line" "$file" "$1" "$testcase"
	       fi
	       if [ $isSuccess -eq 0 ]; then
		       attack_cookie "$line" "$file" "$1" "$testcase"
	       fi
           done < "$file"
         fi
      done
      if [ $isSuccess -eq 1 ]; then
		echo "Attack against $testcase was successful"
      else
		echo "Unable to find an effective attack against $testcase"
      fi
   done
}

echo "Validating arguments..."
check_args $1 $2 $3
echo "Arguments successfully validated."

echo "Submitting payloads..."
attack $1 $2 $3

