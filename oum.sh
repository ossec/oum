#!/bin/bash
# Copyright Atomicorp 2021
# https://www.atomicorp.com
#
# AGPL 3.0
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Affero GNU General Public License (AGPL)
#


# Globals
VERSION=0.4
OSSEC_HOME=/var/ossec
SERVER=updates.atomicorp.com
OSSEC_CRS_RULES_VERSION=0
OSSEC_CRS_THREAT_VERSION=0
OSSEC_CRS_RULES_VERSION_CURRENT=0
OSSEC_CRS_THREAT_VERSION_CURRENT=0

# Command line arguments
command=$1


# Functions
prereq_check() {
	declare -a PREREQS=("curl" "tar" "gzip" "bc" )
	IS_GOOD="1"

	for PREREQ in "${PREREQS[@]}"; do
	    which $PREREQ > /dev/null 2>&1

	    if [ "$?" -ne "0" ]; then
	      IS_GOOD="0"
	      echo " ERROR: $PREREQ not found. $PREREQ must be installed."
	    fi
	done

	if [ ! -d /var/ossec ]; then
	    IS_GOOD="0"
	    echo " ERROR: OSSEC package not found. OSSEC must be installed."
	fi

	if [ "$IS_GOOD" -ne "1" ]; then
	    echo
	    echo "Prerequisite check failed. Exiting!"
	    echo
	    exit 1
	fi

}

function ossec_check() {
        # Check for globbing
        if ! grep -q decoders.d /var/ossec/etc/ossec.conf ; then
                echo
                echo
		echo "########################################################################"
                echo "  WARNING: /var/ossec/etc/ossec.conf is not configured for decoders.d"
                echo "  replace the <rules></rules> section with:"
                echo "  <rules>"
                echo "          <decoder_dir pattern=\".xml$\">etc/decoders.d</decoder_dir>"
                echo "          <rule_dir pattern=\".xml$\">etc/rules.d</rule_dir>"
                echo "          <list>etc/lists/threat</list>"
                echo "  </rules>"
		echo "########################################################################"
                echo
                echo
        fi

}


function rawurlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""

    for ((pos = 0; pos < strlen; pos++)); do
        c=${string:$pos:1}
        case "$c" in
        [-_.~a-zA-Z0-9]) o="${c}" ;;
        *) printf -v o '%%%02x' "'$c" ;;
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
    REPLY="${encoded}"
}


download() {

  URL=$1
  FILENAME=$2
  if [ $DEBUG ]; then
    OPTS=""
  else
    OPTS="-s"
  fi

  if [ $INSECURE ]; then
    OPTS="--insecure"
  fi

  RESPONSE=$(curl --write-out '%{http_code}' ${OPTS} ${URL} -o ${FILENAME})

  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "ERROR: Download failed with ERROR (${RETVAL})"
    if [ ${RETVAL} -eq 60 ]; then
	echo
      	echo "  ERROR: Peer certificate cannot be authenticated with known CA certificates."
	echo
    fi
    echo
    exit 1
  fi

  if [[ "${RESPONSE}" == 401 ]] ; then
	echo 
	echo "  ERROR: request returned HTTP error code 401 [Username/Password Invalid]"
	echo
	exit 1
  elif [[ "${RESPONSE}" != 200 ]] ; then
	echo 
	echo "  ERROR: request returned HTTP error code ${RESPONSE}"
	echo
	exit 1

  fi
}

show_help() {
  echo
  echo "OSSEC Updater Modified (OUM) $VERSION"
  echo
  echo "Usage: oum [options] COMMAND "
  echo
  echo " List of Commands:"
  echo
  echo "  help			Display a helpful usage message"
  echo "  list			List pending updates"
  echo "  update		Update system"
  echo "  configure		Configure system"
  echo "  version		Display version"
  echo
}


load_config() {
  if [ ! -f ${OSSEC_HOME}/etc/oum.conf ]; then
    echo
    echo "ERROR: $OSSEC_HOME/etc/oum.conf not found"
    echo
    exit 1
  fi
  source ${OSSEC_HOME}/etc/oum.conf

}

check_version() {
  if [ -f ${OSSEC_HOME}/tmp/VERSION ]; then
    rm -f ${OSSEC_HOME}/tmp/VERSION
  fi
  download  https://${SERVER}/channels/rules/VERSION ${OSSEC_HOME}/tmp/VERSION


        # Load old version
        if [ -f ${OSSEC_HOME}/var/VERSION ]; then
                source ${OSSEC_HOME}/var/VERSION
                OSSEC_CRS_RULES_VERSION_CURRENT=${OSSEC_CRS_RULES_VERSION}
                OSSEC_CRS_THREAT_VERSION_CURRENT=${OSSEC_CRS_THREAT_VERSION}
        else
                OSSEC_CRS_RULES_VERSION_CURRENT=0
                OSSEC_CRS_THREAT_VERSION_CURRENT=0
        fi

}

update_version() {
  release=$1
  version=$2
  if [ ! -f ${OSSEC_HOME}/var/VERSION ]; then
    echo "OSSEC_CRS_RULES_VERSION=0" > ${OSSEC_HOME}/var/VERSION
    echo "OSSEC_CRS_THREAT_VERSION=0" >> ${OSSEC_HOME}/var/VERSION

  fi

  sed -i "s/${release}.*/${release}=${version}/g" ${OSSEC_HOME}/var/VERSION
}

show_updates() {

  check_version

  source ${OSSEC_HOME}/tmp/VERSION

  if (( $(echo "$OSSEC_CRS_RULES_VERSION_CURRENT < $OSSEC_CRS_RULES_VERSION" |bc -l) )); then
    ARRAY1[0]="OSSEC-CRS-Rules ${OSSEC_CRS_RULES_VERSION}"
  fi

  if [ ${OSSEC_CRS_THREAT_VERSION_CURRENT} -lt ${OSSEC_CRS_THREAT_VERSION} ]; then
    ARRAY1[1]="Atomicorp-Threatfeed ${OSSEC_CRS_THREAT_VERSION}"
  fi

  if [ ${#ARRAY1[@]} -ge 1 ]; then
    echo "Available Upgrades"
    for i in ${!ARRAY1[@]}; do
      printf "%-32s" ${ARRAY1[i]}
      printf "\n"
    done
  else
	echo "No updates available"
  fi


}

update_rules() {


  echo "  Downloading Rule update: ${OSSEC_CRS_RULES_VERSION}"
  download https://${USERNAME}:${PASSWORD}@${SERVER}/channels/rules/ossec/ossec-crs-rules-${OSSEC_CRS_RULES_VERSION}.tar.gz ${OSSEC_HOME}/tmp/ossec-crs-rules-${OSSEC_CRS_RULES_VERSION}.tar.gz

  pushd ${OSSEC_HOME}/tmp/ >/dev/null
    if [ -d ossec-rules ]; then
      rm -rf ossec-rules
    fi
    echo -n "  Extracting archive: "
    tar xf ossec-crs-rules-${OSSEC_CRS_RULES_VERSION}.tar.gz
    if [ $? -ne 0 ]; then
      echo "Failed"
      echo "  ERROR: archive could not be extracted"
      exit 1
    else
      echo "OK"
    fi

    # Back up rules
    echo -n "  Backup current rules: "
    if [ -d ${OSSEC_HOME}/var/backup ]; then
      rm -rf ${OSSEC_HOME}/var/backup
    fi
    mkdir -p ${OSSEC_HOME}/var/backup/decoders.d/
    mkdir -p ${OSSEC_HOME}/var/backup/rules.d/
    cp -a ${OSSEC_HOME}/etc/decoders.d/*xml ${OSSEC_HOME}/var/backup/decoders.d/ 2>/dev/null
    cp -a ${OSSEC_HOME}/etc/rules.d/*xml ${OSSEC_HOME}/var/backup/rules.d/ 2>/dev/null
    echo "OK"

    echo -n "  Applying base rule policy: "
    if [ ! -d  ${OSSEC_HOME}/etc/decoders.d/ ]; then
  mkdir -p ${OSSEC_HOME}/etc/decoders.d/
    fi
    rm -f ${OSSEC_HOME}/etc/decoders.d/*crs*xml
    if [ ! -d  ${OSSEC_HOME}/etc/rules.d/ ]; then
  mkdir -p ${OSSEC_HOME}/etc/rules.d/
    fi
    rm -f ${OSSEC_HOME}/etc/rules.d/*crs*xml
    cp -a ossec-rules/decoders.d/*xml ${OSSEC_HOME}/etc/decoders.d/
    cp -a ossec-rules/rules.d/*xml ${OSSEC_HOME}/etc/rules.d/
    echo "OK"


    echo "  Excluding rulesets"
    # Exclude rules
    for ruleset in $EXCLUDE_RULES; do
      if [ -f ${OSSEC_HOME}/etc/rules.d/${ruleset} ]; then
        echo "    Disabling: $ruleset"
        rm -f ${OSSEC_HOME}/etc/rules.d/${ruleset}
      fi
    done

    # Lint
    echo -n "  Verifying rules: "
    /var/ossec/bin/ossec-analysisd -t >/dev/null 2>&1
    if [ $? -ne 0 ]; then
      echo "Failed"
      echo "  ERROR: Rule update failed lint"
      rm -f ${OSSEC_HOME}/etc/decoders.d/*crs*xml
      rm -f rm -f ${OSSEC_HOME}/etc/rules.d/*crs*xml
      echo "  Reverting to last working copy"
      cp -a ${OSSEC_HOME}/var/backup/decoders.d/ ${OSSEC_HOME}/etc/decoders.d/
      cp -a ${OSSEC_HOME}/var/backup/rules.d/ ${OSSEC_HOME}/etc/rules.d/
      echo
      exit 1
    else
      echo "OK"
      # Update OSSEC_CRS_RULES_VERSION
      update_version OSSEC_CRS_RULES_VERSION ${OSSEC_CRS_RULES_VERSION}
    fi

    UPDATE_OUT+="  OSSEC CRS Rules ${OSSEC_CRS_RULES_VERSION}\n"
    # if this fails restore working rules from backup above
    rm -rf ossec-rules

  popd >/dev/null

}

update_threatfeed() {
  echo "  Downloading Atomicorp Threatfeed update: ${OSSEC_CRS_THREAT_VERSION}"
  download https://${USERNAME}:${PASSWORD}@${SERVER}/channels/rules/ossec/atomicorp-threatfeed-${OSSEC_CRS_THREAT_VERSION}.tar.gz ${OSSEC_HOME}/tmp/atomicorp-threatfeed-${OSSEC_CRS_THREAT_VERSION}.tar.gz
        pushd ${OSSEC_HOME}/tmp/ >/dev/null
                if [ -d atomicorp-threatfeed ]; then
                        rm -rf atomicorp-threatfeed
                fi
                echo -n "  Extracting archive: "
                tar xf atomicorp-threatfeed-${OSSEC_CRS_THREAT_VERSION}.tar.gz
                if [ $? -ne 0 ]; then
                        echo "Failed"
                        echo "  ERROR: archive could not be extracted"
                        exit 1
                else
      echo "OK"

    fi

    if [ ! -d ${OSSEC_HOME}/etc/lists/threat/ ]; then
      mkdir -p ${OSSEC_HOME}/etc/lists/threat/
    fi
    rm -f ${OSSEC_HOME}/etc/lists/threat/* >/dev/null 2>&1
    cp -a atomicorp-threatfeed/* ${OSSEC_HOME}/etc/lists/threat/
    chown root.ossec ${OSSEC_HOME}/etc/lists/threat
    chown root.ossec ${OSSEC_HOME}/etc/lists/threat/*

    # update version
    update_version OSSEC_CRS_THREAT_VERSION ${OSSEC_CRS_THREAT_VERSION}

    # add string to update
    UPDATE_OUT+="  Atomicorp Threatfeed ${OSSEC_CRS_THREAT_VERSION}\n"

    # cleanup
    rm -rf atomicorp-threatfeed


  popd >/dev/null
}

# Apply updates if they are available
update() {

  if [[ "${USERNAME}" == "USERNAME" ]]; then
	echo
	echo "ERROR: oum credentials have not been configured. Run:"
	echo "  oum configure"
	echo
	exit 1
  fi

  check_version
  source ${OSSEC_HOME}/tmp/VERSION
  if [ $DEBUG ]; then
    echo "DEBUG: Compare ${OSSEC_CRS_RULES_VERSION_CURRENT} to ${OSSEC_CRS_RULES_VERSION}"
  fi

  UPDATE_OUT=""

  if (( $(echo "$OSSEC_CRS_RULES_VERSION_CURRENT < $OSSEC_CRS_RULES_VERSION" |bc -l) )); then
    ARRAY1[0]="OSSEC-CRS-Rules ${OSSEC_CRS_RULES_VERSION}"
  fi
  if [ ${OSSEC_CRS_THREAT_VERSION_CURRENT} -lt ${OSSEC_CRS_THREAT_VERSION} ]; then
    ARRAY1[1]="Atomicorp-Threatfeed ${OSSEC_CRS_THREAT_VERSION}"
  fi

  if [[ ${#ARRAY1[@]} -ge 1 ]]; then

    echo "==============================================================================="
    echo " Component			Version"
    echo "==============================================================================="
    echo "Upgrading: "
    for i in ${!ARRAY1[@]}; do
      printf "  %-28s" ${ARRAY1[i]}
      printf "\n"
    done
    echo
    echo
    echo "==============================================================================="
    echo



    if [ ! $YES ]; then
      read -p "Is this ok [y/N]: " -r
      if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Operation aborted."
            exit 1
      fi
    fi

    for i in "${ARRAY1[@]}"; do
      if [[ "$i" =~ "OSSEC-CRS-Rules".* ]]; then
        update_rules
      fi
      if [[ "$i" =~ "Atomicorp-Threatfeed".* ]]; then
        update_threatfeed
      fi

    done



    RESTART=1
    echo
    echo "Upgraded:"
    echo -e "${UPDATE_OUT}"
    echo "Complete!"
  else
	echo "No packages marked for update"
  fi

  # Restart ossec
  if [[ ${RESTART}  ]]; then
    echo -n "  Restarting OSSEC: "
    if [ $DEBUG ]; then
      echo
      ${OSSEC_HOME}/bin/ossec-control restart
    else
      ${OSSEC_HOME}/bin/ossec-control restart >/dev/null 2>&1
      if [ $? -ne 0 ]; then
        echo "Failed"
      else
        echo "OK"
      fi
    fi
    echo
  fi
}

configure() {
  echo
  echo "OSSEC Updater Modified (OUM) $VERSION"

  # Prompt for Username
  read -p "Please enter your subscription username: " user_tmp
  until [ "$user_tmp" != "" ]; do
    echo " ERROR: Username cannot be blank. "
    echo
    read -p "Please enter your subscription username:  " user_tmp
  done

  sed -i 's/^USERNAME.*\"/USERNAME=\"'${user_tmp}'\"/g' $OSSEC_HOME/etc/oum.conf

  PASSCONFIRMED=0
  failed=0
  while [ $PASSCONFIRMED -lt 1 ]; do
    if [ $failed -gt 2 ]; then
        echo "Exiting: too many failed attempts."
        echo
        echo "$(date -u) ERROR: too many failed attempts" >>$LOG
        exit 1
    fi

    read -sp "Please enter your subscription password: " PASSWORD
    echo
    if [ "$PASSWORD" == "" ]; then
        echo "Exiting: Password is blank..."
        exit 1
    fi

    unset PASSWORD2
    read -sp "Please re-enter your subscription password: " PASSWORD2
    echo

    if [ "$PASSWORD" == "$PASSWORD2" ]; then
        PASSCONFIRMED=1
    else
        failed=$(($failed + 1))
        echo
        echo "   Passwords do not match."
        echo
    fi
  done

  sed -i 's/^PASSWORD.*/PASSWORD=\"'${PASSWORD}'\"/g' $OSSEC_HOME/etc/oum.conf

  echo


  TC_TARGET=${SERVER}/channels/rules/ossec/README.md
  ENCPASSWORD=$(rawurlencode $PASSWORD)
  TEST_CREDENTIALS=$(curl -s https://${user_tmp}:$ENCPASSWORD@$TC_TARGET)
  echo
  echo -n "Verifying account: "
  if [[ "$TEST_CREDENTIALS" != "Access to this repo requires registration" ]]; then
	  echo "Failed"
	  echo
	  echo "  Username/Password credentials incorrect. Please confirm the"
	  echo "  correct credentials were entered for the API key."
	  echo
	  exit 1
  else
	  echo "Passed"
  fi



exit



  echo "Configuration Complete!"
  echo
  echo "To update the system, please run:"
  echo "    oum update "
  echo
}


# Installs a package via OUM
install_package() {
  echo
  echo "Installing Package: ${1}"
  echo

  yum install -y --enablerepo=atomic ${1}

  if [ "$?" -ne 0 ]; then
    echo
    echo " ERROR: There was a problem installing ${1}!"
    echo
    exit 1
  else
    echo
    echo " ${1} successfully installed"
  fi


}



# Load our config file
load_config
prereq_check

while getopts ":y" opt; do
  case ${opt} in
    y )
      YES=1
            ;;
       \? )
           echo "Invalid Option: -$OPTARG" 1>&2
           exit 1
           ;;
    esac
done
shift $((OPTIND -1))

case "$command" in

  help)
    show_help
    shift $((OPTIND -1))
    ;;
  list)
        shift
        while getopts ":d:i" opt; do
                case ${opt} in
                        d)
                                DEBUG=1
                                ;;
                        i)
                                INSECURE=1
                                ;;

                esac
        done

    show_updates
    shift $((OPTIND -1))
    ;;
  configure)
    configure
    shift $((OPTIND -1))
    ;;
  update|upgrade)
    shift
    while getopts ":d:insecure" opt; do
      case ${opt} in
        d)
          DEBUG=1
          ;;
        i)
          INSECURE=1
          ;;

      esac
    done

    update
    ossec_check

    ;;

  install)
    shift
    install_package $1
    shift $((OPTIND -1))
    ;;

  version)
    echo "OUM Version: $VERSION"
    shift $((OPTIND -1))
    ;;
  *)
    show_help
    ;;

esac
