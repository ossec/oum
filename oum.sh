#!/usr/bin/env bash
# Copyright Atomicorp 2021
# AGPL 3.0
# Authors:
#   - Charity Ponton
#  - Cody Woods
#  - Frank Iacovino
#  - Juliy V. Chirkov (@juliyvchirkov)
#  - Scott Shinn (@atomicturtle)


# Globals
VERSION=0.5
OSSEC_HOME=/var/ossec
SERVER=updates.atomicorp.com
OSSEC_CRS_RULES_VERSION=0
OSSEC_CRS_THREAT_VERSION=0
OSSEC_CRS_RULES_VERSION_CURRENT=0
OSSEC_CRS_THREAT_VERSION_CURRENT=0

# Functions
print_error() {
    local OPTIND
    local OPTARG
    local opt
    local xtranl
    local tab
    local prefix

    while getopts ":ltTp" opt
    do
        case ${opt} in
            l)
                xtranl='\n'
                ;;
            t)
                tab='\t'
                ;;
            T)
                tab='\t\t'
                ;;
            p)
                prefix='ERROR: '
                ;;
        esac
    done

    shift $((OPTIND - 1))

    >&2 printf "${xtranl}${tab}${prefix}%s\n${xtranl}" "${@}"
}

which() {
    local bindir

    for bindir in $(IFS=: && echo ${PATH})
    do
        [ -x ${bindir}/${1} ] && return 0
    done

    return 1
}

encode_uri_component() {
    [ $# -gt 0 ] && printf "${@}" | perl -pe 's/(.)/sprintf("%%%x", ord($1))/eg'
}

set_perm() {
    chown $(stat -c %U:%G ${OSSEC_HOME}) "${1}"

    if [ -d "${1}" ]
    then
        chmod 550 "${1}"
    else
        [[ ! $(stat -c %A "${1}") =~ x ]] && chmod 640 "${1}"
    fi
}

prereq_check() {
    local NOT_OK
    local -a PREREQS=("curl" "tar" "gzip" "bc" "grep" "sed" "perl" "mktemp" "chown" "chmod" "stat" "find" "cp" "rm" "mv")
    local PREREQ

    for PREREQ in "${PREREQS[@]}"
    do
        ! which ${PREREQ} && NOT_OK=1 && print_error -tp "${PREREQ} not found. ${PREREQ} must be installed."
    done

    [ ! -d ${OSSEC_HOME} ] && NOT_OK=1 && print_error -tp "OSSEC package not found. OSSEC must be installed."

    [ -n "${NOT_OK}" ] && print_error -l "Prerequisite check failed. Exiting!" && exit 1

    # Check for globbing
    if ! grep -q decoders.d ${OSSEC_HOME}/etc/ossec.conf
    then
        print_error
        print_error -t "WARNING: ${OSSEC_HOME}/etc/ossec.conf is not configured for decoders.d"
        print_error -t "replace the <rules></rules> section with:"
        print_error
        print_error -t "<rules>"
        print_error -T '<decoder_dir pattern=".xml$">etc/decoders.d</decoder_dir>'
        print_error -T '<rule_dir pattern=".xml$">etc/rules.d</rule_dir>'
        print_error -T "<list>etc/lists/threat</list>"
        print_error -t "</rules>"
        print_error
    fi
}

download() {
    local RETVAL
    local RESPONSE
    local -a OPTS

    [ -n "${DEBUG}" ] || OPTS+=("-s")
    [ -n "${INSECURE}" ] && OPTS+=("--insecure")

    RESPONSE=$(curl --write-out '%{http_code}' ${OPTS[@]} ${1} -o ${2})
    RETVAL=$?

    if [ ${RETVAL} -ne 0 ]
    then
         [ ${RETVAL} -eq 60 ] && print_error -ltp "Peer certificate cannot be authenticated with known CA certificates."
         print_error -lp "Download failed with ERROR (${RETVAL})"
         exit 1
    fi

    [ ${RESPONSE} -eq 401 ] && print_error -ltp "request returned HTTP error code 401 [Username/Password Invalid]" && exit 1
    [ ${RESPONSE} -ne 200 ] && print_error -ltp "request returned HTTP error code ${RESPONSE}" && exit 1

    set_perm ${2}
}

show_help() {
    printf '\n%s\n\n' "OSSEC Updater Modified (OUM) $VERSION"
    printf '%s\n\n' "Usage: oum [options] COMMAND"
    printf '\t%s\n\n' "List of commands:"
    printf '\t%s\t\t\t%s\n' "help" "Display this usage message"
    printf '\t%s\t\t\t%s\n' "list" "List pending updates"
    printf '\t%s\t\t\t%s\n' "update" "Update system"
    printf '\t%s\t\t%s\n' "configure" "Configure system"
    printf '\t%s\t%s\n' "install package-name" "Install package"
    printf '\t%s\t\t\t%s\n\n' "version" "Display version"
    printf '\t%s\n\n' "List of options:"
    printf '\t%s\t\t\t%s\n' "-y" "Automatic yes to prompts"
    printf '\t%s\t\t\t%s\n' "-d" "Debug mode"
    printf '\t%s\t\t\t%s\n\n' "-i" "Do not verify SSL"
}

load_config() {
  [ ! -f ${OSSEC_HOME}/etc/oum.conf ] && print_error -p "${OSSEC_HOME}/etc/oum.conf not found." && exit 1

  source ${OSSEC_HOME}/etc/oum.conf
}

check_version() {
    [ -f ${OSSEC_HOME}/tmp/VERSION ] && rm -f ${OSSEC_HOME}/tmp/VERSION

    download https://${SERVER}/channels/rules/VERSION ${OSSEC_HOME}/tmp/VERSION

    # Load old version
    if [ -f ${OSSEC_HOME}/var/VERSION ]
    then
        source ${OSSEC_HOME}/var/VERSION

        OSSEC_CRS_RULES_VERSION_CURRENT=${OSSEC_CRS_RULES_VERSION}
        OSSEC_CRS_THREAT_VERSION_CURRENT=${OSSEC_CRS_THREAT_VERSION}
    fi
}

update_version() {
    if [ ! -f ${OSSEC_HOME}/var/VERSION ]
    then
         echo "OSSEC_CRS_RULES_VERSION=0" >${OSSEC_HOME}/var/VERSION
         echo "OSSEC_CRS_THREAT_VERSION=0" >>${OSSEC_HOME}/var/VERSION

         set_perm ${OSSEC_HOME}/var/VERSION
    fi

    sed -i "s/${1}.*/${1}=${2}/g" ${OSSEC_HOME}/var/VERSION
}

show_updates() {
    local -a ARRAY1
    local idx

    check_version

    source ${OSSEC_HOME}/tmp/VERSION

    [ $(echo "${OSSEC_CRS_RULES_VERSION} > ${OSSEC_CRS_RULES_VERSION_CURRENT}" | bc -l) -eq 1 ] &&
        ARRAY1[0]="OSSEC-CRS-Rules ${OSSEC_CRS_RULES_VERSION}"

    [ ${OSSEC_CRS_THREAT_VERSION_CURRENT} -lt ${OSSEC_CRS_THREAT_VERSION} ] &&
        ARRAY1[1]="Atomicorp-Threatfeed ${OSSEC_CRS_THREAT_VERSION}"

    if [ ${#ARRAY1[@]} -gt 0 ]
    then
        printf '%s\n' "Updates available."

        for idx in ${!ARRAY1[@]}
        do
            [ ${idx} -eq 0 ] && printf "\t%s\t\t\t%s\n" ${ARRAY1[$idx]} || printf "\t%s\t\t%s\n" ${ARRAY1[$idx]}
        done
    else
        printf '%s\n' "No available updates."
    fi
}

update_rules() {
    local item

    printf '\n\t%s\n' "Downloading Rule update: ${OSSEC_CRS_RULES_VERSION}"

    download https://$(encode_uri_component ${USERNAME}):$(encode_uri_component ${PASSWORD})@${SERVER}/channels/rules/ossec/ossec-crs-rules-${OSSEC_CRS_RULES_VERSION}.tar.gz ${OSSEC_HOME}/tmp/ossec-crs-rules-${OSSEC_CRS_RULES_VERSION}.tar.gz

    pushd ${OSSEC_HOME}/tmp >/dev/null

    [ -d ossec-rules ] && rm -rf ossec-rules

    printf '\t%s ' "Extracting archive:"

    if tar xf ossec-crs-rules-${OSSEC_CRS_RULES_VERSION}.tar.gz
    then
        printf '%s\n' "OK"
    else
        printf '%s\n' "Failed"
        print_error -tp "archive could not be extracted"
        exit 1
    fi

    rm -f ossec-crs-rules-${OSSEC_CRS_RULES_VERSION}.tar.gz

    while IFS= read -r -d '' item
    do
        set_perm "${item}"
    done < <(find ${OSSEC_HOME}/tmp/ossec-rules -print0)

    # Back up rules
    printf '\t%s ' "Making backup of current rules:"

    [ -d ${OSSEC_HOME}/var/backup ] && rm -rf ${OSSEC_HOME}/var/backup

    for item in ${OSSEC_HOME}/var/backup ${OSSEC_HOME}/var/backup/decoders.d ${OSSEC_HOME}/var/backup/rules.d
    do
        mkdir ${item} && set_perm ${item}
    done

    [ -d ${OSSEC_HOME}/etc/decoders.d ] && cp -a ${OSSEC_HOME}/etc/decoders.d/* ${OSSEC_HOME}/var/backup/decoders.d/

    [ -d ${OSSEC_HOME}/etc/rules.d ] && cp -a ${OSSEC_HOME}/etc/rules.d/* ${OSSEC_HOME}/var/backup/rules.d/

    printf '%s\n' "OK"

    printf '\t%s ' "Applying base rule policy:"

    [ ! -d  ${OSSEC_HOME}/etc/decoders.d ] && mkdir ${OSSEC_HOME}/etc/decoders.d && set_perm ${OSSEC_HOME}/etc/decoders.d
    rm -f ${OSSEC_HOME}/etc/decoders.d/*
    cp -a ossec-rules/decoders.d/* ${OSSEC_HOME}/etc/decoders.d/

    [ ! -d  ${OSSEC_HOME}/etc/rules.d ] && mkdir ${OSSEC_HOME}/etc/rules.d && set_perm ${OSSEC_HOME}/etc/rules.d
    rm -f ${OSSEC_HOME}/etc/rules.d/*
    cp -a ossec-rules/rules.d/* ${OSSEC_HOME}/etc/rules.d/

    printf '%s\n' "OK"

    if [ -n "${EXCLUDE_RULES}" ]
    then
        # Exclude rules
        printf '\t%s\n' "Excluding rulesets."

        for item in ${EXCLUDE_RULES}
        do
            [ -f ${OSSEC_HOME}/etc/rules.d/${item} ] && printf '\t%s\n' "Disabling: ${item}" && rm -f ${OSSEC_HOME}/etc/rules.d/${item}
        done
    fi

    # Lint
    printf '\t%s ' "Verifying rules:"

    if ${OSSEC_HOME}/bin/ossec-analysisd -t >/dev/null 2>&1
    then
        printf '%s\n' "OK"

        # update version
        update_version OSSEC_CRS_RULES_VERSION ${OSSEC_CRS_RULES_VERSION}
    else
        printf '%s\n' "Failed"
        print_error -tp "Rule update failed lint"

        rm -f ${OSSEC_HOME}/etc/decoders.d/*
        rm -f ${OSSEC_HOME}/etc/rules.d/*

        printf '\t%s\n\n' "Reverting to last working copy"

        cp -a ${OSSEC_HOME}/var/backup/decoders.d/* ${OSSEC_HOME}/etc/decoders.d/
        cp -a ${OSSEC_HOME}/var/backup/rules.d/* ${OSSEC_HOME}/etc/decoders.d/

        exit 1
    fi

    # add string to update
    UPDATE_OUT+=("OSSEC CRS Rules ${OSSEC_CRS_RULES_VERSION}")

    # cleanup
    rm -rf ossec-rules

    popd >/dev/null
}

update_threatfeed() {
    local item

    printf '\n\t%s\n' "Downloading Atomicorp Threatfeed update: ${OSSEC_CRS_THREAT_VERSION}"

    download https://$(encode_uri_component ${USERNAME}):$(encode_uri_component ${PASSWORD})@${SERVER}/channels/rules/ossec/atomicorp-threatfeed-${OSSEC_CRS_THREAT_VERSION}.tar.gz ${OSSEC_HOME}/tmp/atomicorp-threatfeed-${OSSEC_CRS_THREAT_VERSION}.tar.gz

    pushd ${OSSEC_HOME}/tmp >/dev/null

    [ -d atomicorp-threatfeed ] && rm -rf atomicorp-threatfeed

    printf '\t%s ' "Extracting archive:"

    if tar xf atomicorp-threatfeed-${OSSEC_CRS_THREAT_VERSION}.tar.gz
    then
        printf '%s\n' "OK"
    else
        printf '%s\n' "Failed"
        print_error -tp "archive could not be extracted"
        exit 1
    fi

    rm -f atomicorp-threatfeed-${OSSEC_CRS_THREAT_VERSION}.tar.gz

    while IFS= read -r -d '' item
    do
        set_perm "${item}"
    done < <(find ${OSSEC_HOME}/tmp/atomicorp-threatfeed -print0)

    [ ! -d ${OSSEC_HOME}/etc/lists ] && mkdir ${OSSEC_HOME}/etc/lists && set_perm ${OSSEC_HOME}/etc/lists
    [ ! -d ${OSSEC_HOME}/etc/lists/threat ] && mkdir ${OSSEC_HOME}/etc/lists/threat && set_perm ${OSSEC_HOME}/etc/lists/threat

    rm -f ${OSSEC_HOME}/etc/lists/threat/*

    cp -a atomicorp-threatfeed/* ${OSSEC_HOME}/etc/lists/threat/

    # update version
    update_version OSSEC_CRS_THREAT_VERSION ${OSSEC_CRS_THREAT_VERSION}

    # add string to update
    UPDATE_OUT+=("Atomicorp Threatfeed ${OSSEC_CRS_THREAT_VERSION}")

    # cleanup
    rm -rf atomicorp-threatfeed

    popd >/dev/null
}

# Apply updates if they are available
update() {
    local -a UPDATE_OUT
    local RESTART=""
    local -a ARRAY1
    local idx

    [[ -z "${USERNAME}" || "${USERNAME}" = "USERNAME" ]] && print_error -lp "oum credentials have not been configured. Run:\n\toum configure" && exit 1

    check_version

    source ${OSSEC_HOME}/tmp/VERSION

    [ ${DEBUG} ] && printf '%s\n' "DEBUG: Compare ${OSSEC_CRS_RULES_VERSION_CURRENT} to ${OSSEC_CRS_RULES_VERSION}"

    [ $(echo "${OSSEC_CRS_RULES_VERSION} > ${OSSEC_CRS_RULES_VERSION_CURRENT}" | bc -l) -eq 1 ] &&
        ARRAY1[0]="OSSEC-CRS-Rules ${OSSEC_CRS_RULES_VERSION}"

    [ ${OSSEC_CRS_THREAT_VERSION_CURRENT} -lt ${OSSEC_CRS_THREAT_VERSION} ] &&
        ARRAY1[1]="Atomicorp-Threatfeed ${OSSEC_CRS_THREAT_VERSION}"

    if [ ${#ARRAY1[@]} -gt 0 ]
    then
        printf '=%.0s' {1..79}
        printf '\n\t%s\t\t\t%s\n' "Component" "Version"
        printf '=%.0s' {1..79}
        printf '\n%s\n' "Upgrading:"

        for idx in ${!ARRAY1[@]}
        do
            [ ${idx} -eq 0 ] && printf "\t%s\t\t\t%s\n" ${ARRAY1[$idx]} || printf "\t%s\t\t%s\n" ${ARRAY1[$idx]}
        done
        printf '=%.0s' {1..79}
        printf '\n'

        if [ -z "${YES}" ]
        then
            read -rp "Is this ok [Y/N]: " -n1

            [[ ! ${REPLY} =~ ^[Yy]$ ]] && print_error -l "Operation aborted." && exit 1
        fi

        for idx in ${!ARRAY1[@]}
        do
            [[ ${ARRAY1[$idx]} =~ "OSSEC-CRS-Rules" ]] && update_rules
            [[ ${ARRAY1[$idx]} =~ "Atomicorp-Threatfeed" ]] && update_threatfeed
        done

        RESTART=1

        printf '\n%s\n' "Upgraded:"

        for idx in ${!UPDATE_OUT[@]}
        do
            printf '\t%s\n' "${UPDATE_OUT[$idx]}"
        done

        printf '%s\n\n' "Complete!"
    else
        printf '%s\n' "No packages marked for update."
    fi

    # Restart ossec
    if [ -n "${RESTART}" ]
    then
        printf '\t%s ' "Restarting OSSEC:"

        if [ -n "$DEBUG" ]
        then
            printf '\n'
            ${OSSEC_HOME}/bin/ossec-control restart
        else
            ${OSSEC_HOME}/bin/ossec-control restart >/dev/null 2>&1
        fi

        [ $? -eq 0 ] && printf '%s\n\n' "OK" || printf '%s\n\n' "Failed"
    fi
}

configure() {
    local conf_cur
    local conf_tmp
    local user_tmp
    local pass_tmp

    printf '\n%s\n' "OSSEC Updater Modified (OUM) ${VERSION}"

    conf_cur=$(mktemp -u -p $OSSEC_HOME/etc oum.XXXXXXXX.conf)
    conf_tmp=$(mktemp -u -p $OSSEC_HOME/etc oum.XXXXXXXX.conf)

    cp -a ${OSSEC_HOME}/etc/oum.conf ${conf_cur}
    cp -a ${conf_cur} ${conf_tmp}

    # Prompt for Username
    read -rp "Please enter your subscription username [Default: ${USERNAME}]: " user_tmp

    if [[ ${USERNAME} ]] && [[ $user_tmp == "" ]]; then
        user_tmp=${USERNAME}
	fi

    until [ -n "${user_tmp}" ]; do
        print_error -ltp "Username cannot be blank."

        read -rp "Please enter your subscription username [Default: ${USERNAME}]: " user_tmp
    done

    sed -i '/USERNAME=.*/d' ${conf_cur}

    echo "USERNAME=$(printf %q "${user_tmp}")" >${conf_tmp}

    # Prompt for Password
    read -rsp "Please enter your subscription password [Default: ${PASSWORD}] " pass_tmp

    if [[ ${PASSWORD} ]] && [[ $pass_tmp == "" ]]; then
        pass_tmp=${PASSWORD}
	fi

    until [ -n "${pass_tmp}" ]; do 
        print_error -ltp "Password cannot be blank."

        read -rsp "Please enter your subscription password [Default: ${PASSWORD}] " pass_tmp
    done

    sed -i '/PASSWORD=.*/d' ${conf_cur}

    echo "PASSWORD=$(printf %q "${pass_tmp}")" >>${conf_tmp}

    cat ${conf_cur} >>${conf_tmp}

    rm -f ${conf_cur}

    mv -f ${conf_tmp} ${OSSEC_HOME}/etc/oum.conf

    printf '\n%s\n\n%s\n\t%s\n\n' "Configuration Complete!" "To update the system, please run:" "oum update"
}

# Installs a package via OUM
install_package() {
    local PKG="unknown"

    [ -z "${1}" ] && print_error -p "package not specified. To install a package, please run:" && print_error -t "oum install package-name" && exit 1

    printf '\n%s\n\n' "Installing Package: ${1}"

    which yum && PKG="rpm"
    which apt-get && PKG="deb"

    if [ "${PKG}" = "rpm" ]
    then
        yum install -y --enablerepo=atomic ${1}
    elif [ "${PKG}" = "deb" ]
    then
        DEBIAN_FRONTEND=noninteractive apt-get -y install ${1}
    else
        print_error -lp "installation not supported."

        exit 1
    fi

    if [ $? ]
    then
        printf '\n\t%s\n\n' "${1} successfully installed."
    else
        print_error -ltp "There was a problem installing ${1}!"

        exit 1
    fi
}

while getopts ":ydi" opt
do
    case ${opt} in
        y)
            YES=1
            ;;
        d)
            DEBUG=1
            ;;
        i)
            INSECURE=1
            ;;
        \?)
            print_error -ltp "invalid option -${OPTARG}" && show_help && exit 1
            ;;
    esac
done

shift $((OPTIND - 1))

[ -n "${DEBUG}" ] && set -x

# Load our config file
load_config

prereq_check

# Command line arguments
command=${1}

shift

case "${command}" in
    list)
        show_updates
        ;;
    configure)
        configure
        ;;
    update)
        update
        ;;
    install)
        install_package ${1}
        ;;
    version)
        printf '\n%s\n' "OSSEC Updater Modified (OUM) Version: $VERSION"
        printf '%s\n\n' "  Copyright Atomicorp, Inc. 2021"
        ;;
    *)
        show_help
        ;;
esac
