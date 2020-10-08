#!/bin/bash
# Copyright Atomicorp 2020
# AGPL 3.0

# Globals
VERSION=0.1
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

#  echo "Analyzing system for required packages: "

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

#  echo " INFO: Prerequisite check complete. [PASS]"
#  echo

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

  curl ${OPTS} ${URL} -o ${FILENAME}
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "ERROR: Download failed with Error (${RETVAL})"
    if [ ${RETVAL} -eq 60 ]; then
      echo "  Peer certificate cannot be authenticated with known CA certificates."
    fi
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
    echo "Error: $OSSEC_HOME/etc/oum.conf not found"
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
                OSSEC_CRS_THREAT_CURRENT=${OSSEC_CRS_THREAT_VERSION}
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
      echo "  Error: archive could not be extracted"
      exit 1
    else
      echo "OK"
    fi

    # Back up rules
    echo -n "  Back up current rules: "
    if [ -d ${OSSEC_HOME}/var/backup ]; then
      rm -rf ${OSSEC_HOME}/var/backup
    fi
    mkdir -p ${OSSEC_HOME}/var/backup/decoders.d/
    mkdir -p ${OSSEC_HOME}/var/backup/rules.d/
    cp -a ${OSSEC_HOME}/etc/decoders.d/*xml ${OSSEC_HOME}/var/backup/decoders.d/
    cp -a ${OSSEC_HOME}/etc/rules.d/*xml ${OSSEC_HOME}/var/backup/rules.d/
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
      echo "  Error: Rule update failed lint"
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
                        echo "  Error: archive could not be extracted"
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

    echo "========================================================================================================="
    echo " Component			Version"
    echo "========================================================================================================="
    echo "Upgrading: "
    for i in ${!ARRAY1[@]}; do
      printf "  %-28s" ${ARRAY1[i]}
      printf "\n"
    done
    echo
    echo
    echo "========================================================================================================="
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
  read -p "Please enter your subscription username [Default: ] " user_tmp
  until [ "$user_tmp" != "" ]; do
    echo " ERROR: Username cannot be blank. "
    echo
    read -p "Please enter your subscription username [Default: ] " user_tmp
  done

  sed -i 's/\"USERNAME\"/\"'${user_tmp}'\"/g' $OSSEC_HOME/etc/oum.conf

  # Prompt for Password
  read -sp "Please enter your subscription password [Default: ] " pass_tmp
  until [ "$pass_tmp" != "" ]; do
    echo " ERROR: Password cannot be blank. "
    echo
    read -p "Please enter your subscription password [Default: ] " pass_tmp
  done

  sed -i 's/\"PASSWORD\"/\"'${pass_tmp}'\"/g' $OSSEC_HOME/etc/oum.conf
  echo
  echo "Configuration Complete!"
  echo
  echo "To update the system, please run:"
  echo "    oum update "
  echo
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
  update)
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

    ;;
  version)
    echo "OUM Version: $VERSION"
    shift $((OPTIND -1))
    ;;
  *)
    show_help
    ;;

esac
