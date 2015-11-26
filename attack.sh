# Copyright (C) 2015-2016 Myriam Leggieri <iammyr@email.com>
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.

#!/bin/bash

ERROR_ARGS="Error: Argument/s not provided."
USAGE="Usage: $0 <web app URL pefix> <file with web app URL suffix to test> <directory with files with payloads>"
ERROR_INVALID="Error: Invalid argument/s provided."


check_existence(){
   if [[ -z $1 ]] || [[ -z $2 ]] || [[ -z $3 ]]
   then
     echo $ERROR_ARGS
     echo $USAGE
     return $FALSE
   fi
   return $TRUE
}

check_validity(){
   if [[ $1 != http://* ]] || [[ ! -r $2 ]] || [[ ! -d $3 ]]
   then
     echo $ERROR_INVALID
     echo $USAGE
     return $FALSE
   fi
   return $TRUE    
}

check_args(){
   check_existence $1 $2 $3
   existence=$?
   check_validity $1 $2 $3
   validity=$?
   if [[ ! existence ]] || [[ ! validity ]]
   then
     exit 2
   fi
   return $TRUE
}

init_file(){
   if [[ -r $4 ]]; then
     rm $4
   fi
}

error_check(){
   if [[ $1 == Error* ]]; then
      echo "Error: curl for line $2 in file $3 was not executed." >> error-leftover.log
      return $FALSE
   fi
   return $TRUE
}

attack-simple(){
   echo "Submitting payload $1 from file $2"
   payload="vector=$1"
   status=$(curl -X POST -d "$payload" $3/$4 --trace-ascii dump.txt )
   echo "status=$status"
   final=error_check $status $1 $2
   return $final
}

attack-stored-procedure(){
               echo "Submitting payload $1 from file $2 (attacking stored procedures)"
               #escape apostrophes by doubling them (as required by stored procedures to succeed)
               content=cat $1 | sed 's/'"'"'/'"'"''"'"'/g'
               payload="vector='verifyUserPassword(foo,$content)'"
               status=$(curl -X POST -d "$payload" $3/$4 --trace-ascii dump.txt )
               echo "status=$status"
               final=error_check $status $1 $2
               return $final
}

attack-header-based(){
   echo "Submitting attack vector $1 from file $2 inside the request header"
   payload="vector: $1"
   status=$(curl -X POST -H "$payload" $3/$4)
   echo "status=$status"
   final=error_check $status $1 $2
   return $final      
}

attack-param-name(){
   echo "Submitting attack vector $1 from file $2 as the payload parameter's name"
   payload="$1=vector"
   status=$(curl -X POST -H "$payload" $3/$4)
   echo "status=$status"
   final=error_check $status $1 $2
   return $final
}

attack(){
   path="$3/*"
   echo "path $path"
   for testcase in $(cat $2); do
      for file in $path; do
         if [[ $file == *.pay ]]; then
            echo "Reading from file $file"
            while IFS='' read -r line || [[ -n "$line" ]]; do
               line=$( echo $line | sed s/\"/\\\"/g )  i
               attack_simple $line $file $1 $testcase
               attack_stored-procedure $line $file $1 $testcase
               attack-header-based $line $file $1 $testcase
               attack-param-name $line $file $1 $testcase
            done < "$file"
         fi
      done
   done
}

echo "Validating arguments..."
check_args $1 $2 $3
echo "Arguments successfully validated."

echo "Submitting payloads..."
attack $1 $2 $3
echo "Payloads successfully submitted."
