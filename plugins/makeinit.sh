plugin_init="$1"
# mechanism plugins
for mech in anonymous crammd5 digestmd5 scram gssapiv2 kerberos4 login ntlm otp passdss plain srp gs2; do
    if [ "_${plugin_init}" = "_${mech}_init.c" ] || [ "_${plugin_init}" = "_" ];then
        sed -e "s/MECHANISM/$mech/g" ../win32/init_mechanism.c > ${mech}_init.c
        echo >> ${mech}_init.c
        echo "generating ${mech}_init.c"
    fi
done

# auxprop plugins
for auxprop in sasldb sql ldapdb; do
    if [ "_${plugin_init}" = "_${auxprop}_init.c" ] || [ "_${plugin_init}" = "_" ];then
        sed -e "s/AUXPROP_REPLACE/$auxprop/g" ../win32/init_auxprop.c > ${auxprop}_init.c
        echo >> ${auxprop}_init.c
        echo "generating ${auxprop}_init.c"
    fi
done

# ldapdb is also a canon_user plugin
if [ "_${plugin_init}" = "_ldapdb_init.c" ] || [ "_${plugin_init}" = "_" ];then
    echo "SASL_CANONUSER_PLUG_INIT( ldapdb )" >> ldapdb_init.c
fi
