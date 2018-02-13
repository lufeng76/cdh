from __future__ import with_statement
from fabric import tasks
from fabric.api import *
from fabric.contrib.console import confirm
from fabric.contrib.files import *
from fabric.network import disconnect_all

env.roledefs = {
    "namenode": [
        'fengstream-1.gce.cloudera.com'
    ],
    "datanode": [
        'fengstream-2.gce.cloudera.com',
        'fengstream-3.gce.cloudera.com',
        'fengstream-4.gce.cloudera.com',
    ],    
    "cluster": [
        'fengstream-1.gce.cloudera.com',
        'fengstream-2.gce.cloudera.com',
        'fengstream-3.gce.cloudera.com',
        'fengstream-4.gce.cloudera.com',
    ],
    "cdsw": [
        'timcdsw-5.vpc.cloudera.com'
    ],
}

env.user = 'root'
env.password = 'cloudera'

env.mysql_user = 'root'
env.mysql_password = 'root123'

#repo mode
env.mariadb_baseurl = 'http://yum.mariadb.org/10.2.1/centos7-amd64/rpms/'
env.mariadb_jdbc = 'https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-5.1.42.tar.gz'
env.mariadb_baseurl_local = 'http://fengstream-1.gce.cloudera.com/MariaDB/'

#repo mode
env.cm_baseurl = 'http://archive.cloudera.com/cm5/redhat/7/x86_64/cm/5.13.0/RPMS/x86_64/'
env.cm_baseurl_local = 'http://fengstream-1.gce.cloudera.com/cm5/'

#parcel mode
env.cdh_parcel = 'http://archive.cloudera.com/cdh5/parcels/5.13.0/CDH-5.13.0-1.cdh5.13.0.p0.29-el7.parcel'
#env.cdh_parcel = 'http://archive.cloudera.com/cdh5/parcels/5.12/CDH-5.12.1-1.cdh5.12.1.p0.3-el7.parcel'
#env.cdh_parcel = 'http://archive.cloudera.com/cdh5/parcels/5.12.0/CDH-5.12.0-1.cdh5.12.0.p0.29-el7.parcel'

#parcel mode
env.kudu_parcel = 'http://archive.cloudera.com/kudu/parcels/5.12.1/KUDU-1.4.0-1.cdh5.12.1.p0.10-el7.parcel'

#parcel mode
env.kafka_parcel = 'http://archive.cloudera.com/kafka/parcels/3.0.0/KAFKA-3.0.0-1.3.0.0.p0.40-el7.parcel'

#parcel mode
env.anaconda_parcel = 'https://repo.continuum.io/pkgs/misc/parcels/Anaconda-4.2.0-el7.parcel'

#parcel mode
env.spark_parcel = 'http://archive.cloudera.com/spark2/parcels/2.2.0/SPARK2-2.2.0.cloudera1-1.cdh5.12.0.p0.142354-el7.parcel'
env.spark_csd = 'http://archive.cloudera.com/spark2/csd/SPARK2_ON_YARN-2.2.0.cloudera1.jar'
env.spark_baseurl_local = 'http://fengstream-1.gce.cloudera.com/spark2/'

#parcel mode
env.cdsw_parcel = 'http://archive.cloudera.com/cdsw/1/parcels/1.2.0/CDSW-1.2.0.p1.183075-el7.parcel'
env.cdsw_csd = 'http://archive.cloudera.com/cdsw/1/csd/CLOUDERA_DATA_SCIENCE_WORKBENCH-1.2.0.jar'
env.cdsw_baseurl_local = 'http://fengstream-1.gce.cloudera.com/cdsw/'

env.jdk18_baseurl = 'http://archive.cloudera.com/director/redhat/7/x86_64/director/2.5.0/RPMS/x86_64/oracle-j2sdk1.8-1.8.0+update121-1.x86_64.rpm'
env.jce8_baseurl = 'http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip'

env.config_local = '/Users/feng.xu/cdh_setup_v1/config'
env.realm_string = 'VPC.CLOUDERA.COM'
env.princ_string = 'cloudera-scm'


def yum_install(package="openssh-server"):
    with settings(warn_only=True):
        if sudo("yum list installed {}".format(package)).failed:
            if confirm("Install {} via yum install?".format(package), default=False) == True:
                if sudo("yum install {}".format(package), pty=True).failed:
                    print("{} unsuccessfully installed!".format(package))
                else:
                    print("{} successfully installed!".format(package))
            else:
                print("{} not installed!".format(package))
        else:
            print("{} already Exists!".format(package))


def yum_remove(package):
    with settings(warn_only=True):
        if sudo("yum list installed {}".format(package)).failed:
            print("{} already uninstalled!".format(package))
        else:
            if confirm("UnInstall {} via yum remove?".format(package), default=False) == True:
                if sudo("yum remove {}".format(package), pty=True).failed:
                    print("{} unsuccessfully removed!".format(package))
                else:
                    print("{} successfully removed!".format(package))
            else:
                print("{} not removed!".format(package))

@roles("cluster")
def ip_tables():
    sudo("systemctl stop firewalld")
    sudo("systemctl disable firewalld")
    sudo("systemctl status firewalld")

@roles("cluster")
def ntp():
    yum_install("chrony")
    if confirm("Do chrony already run?", default=False) == False:
        sudo("systemctl enable chronyd.service")
        sudo("systemctl restart chronyd.service")
        sudo("chronyc sources -v")
    else:
        print("chronyc is already installed and running!")

@roles("cluster")
def max_open_files():
    if confirm("Change number of open files for hdfs, mapred, and hbase on {}?".format(env.host_string), default=False) == True:
        sudo('echo "hdfs - nofile 32768" >> /etc/security/limits.conf')
        sudo('echo "mapred - nofile 32768" >> /etc/security/limits.conf')
        sudo('echo "hbase - nofile 32768" >> /etc/security/limits.conf')

        sudo('echo "hdfs - noproc 32768" >> /etc/security/limits.conf')
        sudo('echo "mapred - noproc 32768" >> /etc/security/limits.conf')
        sudo('echo "hbase - noproc 32768" >> /etc/security/limits.conf')
    else:
        print("Number of open files/processes not changed on {}".format(env.host_string))

#@roles("cluster")
@roles("cdsw")
def swappiness():
    if confirm("Check swappiness on {}?".format(env.host_string), default=False) == True:
        if sudo("sysctl vm.swappiness").failed:
            print("get value of vm.swappiness failed!")
        else:
            if confirm("Change swappiness to 0?", default=False) == True:
                sudo("sysctl vm.swappiness=0")
                sudo("cat /etc/sysctl.conf")
                if confirm("Add vm.swappiness to sysctl.conf file?", default=False) == True:
                    sudo('echo "vm.swappiness = 0" >> /etc/sysctl.conf')
                else:
                    replace("/etc/sysctl.conf","vm.swappiness.*","vm.swappiness = 0")
                print("Swappiness changed on {}.".format(env.host_string))
            else:
                print("Swappiness will not be changed.")
    else:
        print("Swappiness not changed on {}".format(env.host_string))

@roles("cluster")
def nscd():
    yum_install("nscd")
    if confirm("Do nscd already run?", default=False) == False:
        sudo("systemctl start nscd.service")
        sudo("systemctl enable nscd.service")
    else:
        print("nscd is already installed and running!")

@roles("cluster")
def selinux():
    if exists("/etc/selinux/config"):
        sudo("cat /etc/selinux/config")
        if confirm("Disable SELinux on {}?".format(env.host_string), default=False) == True:
            sudo('echo "SELINUX=disabled" > /etc/selinux/config')
    else:
        print("SELinux file doesn't exist on: {}".format(env.host_string))

@roles("cluster")
def THP():
    if confirm("Check Disable Transparent Huge Pages on {}?".format(env.host_string), default=False) == True:
        with settings(warn_only=True):
            if sudo('grep "echo never > /sys/kernel/mm/transparent_hugepage/defrag" /etc/rc.local').failed:
                sudo('echo "echo never > /sys/kernel/mm/transparent_hugepage/defrag" >> /etc/rc.local')
            if sudo('grep "echo never > /sys/kernel/mm/transparent_hugepage/enabled" /etc/rc.local').failed:
                sudo('echo "echo never > /sys/kernel/mm/transparent_hugepage/enabled" >> /etc/rc.local')

        if sudo('echo never > /sys/kernel/mm/transparent_hugepage/defrag').failed:
            print("disable Transparent Huge Pages from defrag failed!")
        else:
            print("disable Transparent Huge Pages from defrag successfully!")
        if sudo('echo never > /sys/kernel/mm/transparent_hugepage/enabled').failed:
            print("disable Transparent Huge Pages from enabled failed!")
        else:
            print("disable Transparent Huge Pages from enabled successfully!")
    else:
        print("Transparent Huge Pages not checked on {}".format(env.host_string))


def file_upload(file_name,target_path):
    if confirm("Move {} file to {} @ {}?".format(file_name,target_path,env.host_string), default=False) == True:
        if put(file_name,target_path,use_sudo=True).failed:
            print("Upload of {} failed!".format(file_name))
        else:
            print("Upload of {} success!".format(file_name))
    else:
        print("File not moved to {}!".format(env.host_string))

def file_download(file_name,target_path):
    if confirm("Move {} @ {} file to {}?".format(file_name,env.host_string,target_path), default=False) == True:
        if get(file_name,target_path,use_sudo=True).failed:
            print("Download of {} failed!".format(file_name))
        else:
            print("Download of {} success!".format(file_name))
    else:
        print("File @ {} not moved to local area!".format(env.host_string))


def chmod(file_name, modes):
    if exists(file_name):
        if confirm("Change mode of " + file_name + " to " + modes + "?", default=False) == True:
            if sudo("chmod " + modes + " " + file_name).failed:
                print("Change Mode Failed!")
            else:
                print("Change Mode Success!")
        else:
            print(file_name + " mode not changed!")
    else:
        print(file_name + " doesn't exist on: " + env.host_string)


def chown(dir_name, owner):
    if exists(dir_name):
        if confirm("Change ownership of " + dir_name + " to " + owner + "?", default=False) == True:
            if sudo("chown -R " + owner + ":" + owner + " " + dir_name).failed:
                print("Change Owner to " + owner + " Failed!")
            else:
                print("Change Owner to " + owner + " Success!")
        else:
            print(dir_name + " owner not changed!")
    else:
        print(dir_name + " doesn't exist on: " + env.host_string)


def mkdir(dir_name):
    if exists(dir_name):
        print(dir_name + " already exist on: " + env.host_string)
    else:
        if confirm("Create directory " + dir_name + " ?", default=False) == True:
            if sudo("mkdir " + dir_name).failed:
                print("Directory creation of " + dir_name + " Failed!")
            else:
                print("Directory creation of " + dir_name + " Success!")
        else:
            print(dir_name + " directory not created!")



def rm_dir(dir_name):
    if exists(dir_name):
        if confirm("Permanently Remove " + dir_name + " on " + env.host_string + "?", default=False) == True:
            if sudo("rm -r " + dir_name).failed:
                print("Removal of " + dir_name + " Failed!")
            else:
                print("Removal of " + dir_name + " Success!")
        else:
            print(dir_name + " directory not removed!")
    else:
        print(dir_name + " doesn't exist on: " + env.host_string)

def rm_file(file_name):
    if exists(file_name):
        if confirm("Permanently Remove " + file_name + " on " + env.host_string + "?", default=False) == True:
            if sudo("rm " + file_name).failed:
                print("Removal of " + file_name + " Failed!")
            else:
                print("Removal of " + file_name + " Success!")
        else:
            print(file_name + " file not removed!")
    else:
        print(file_name + " doesn't exist on: " + env.host_string)


def cp_file(file_name,target_name):
    if exists(file_name):
        if confirm("Copy {} on {} to {}?".format(file_name,env.host_string,target_name), default=False) == True:
            if sudo("cp {} {}".format(file_name,target_name)).failed:
                print("Copy of {} Failed!".format(file_name))
            else:
                print("Copy of {} to {} Success!".format(file_name, target_name))
        else:
            print("{} file not copied!".format(file_name))
    else:
        print("{} doesn't exist on: {}".format(file_name,env.host_string))



def replace(file_name,orig_string,new_string):
    if exists(file_name):
        if confirm("Search {} for {} and replace with {}?".format(file_name,orig_string,new_string), default=False) == True:
            if sudo("sed -i.bak$(date +'%s') \'s/{}/{}/g\' {}".format(orig_string,new_string,file_name)).failed:
                print("Replace of " + file_name + " Failed!")
            else:
                print("Replace of " + file_name + " Success!")
        else:
            print(file_name + " file not replaced!")
    else:
        print(file_name + " doesn't exist on: " + env.host_string)


def append(file_name,match_string,append_string):
    if exists(file_name):
        if confirm("Search {} for {} and append a new line with {}?".format(file_name,match_string,append_string), default=False) == True:
            if sudo("sed -i.bak$(date +'%s') \'/{}/a {}\' {}".format(match_string,append_string,file_name)).failed:
                print("Append of {} Failed!".format(file_name))
            else:
                print("Append of {} Success!".format(file_name))
        else:
            print("{} file not appended!".format(file_name))
    else:
        print("{} doesn't exist on: {}".format(file_name,env.host_string))


def unzip(file_name,target_path):
    if exists(file_name):
        if confirm("Unzip {} into {}?".format(file_name,target_path), default=False) == True:
            if sudo("unzip {} -d {}".format(file_name,target_path)).failed:
                print("Unzip of {} Failed!".format(file_name))
            else:
                print("Unzip of {} into {} Success!".format(file_name,target_path))
        else:
            print("Nothing to unzip based on response!")
    else:
            print("{} doesn't exist on: {}".format(file_name,env.host_string))



def mysql_install():
    if confirm("Install MySQL server on: " + env.host_string, default=False) == True:
        if sudo("mysql_install_db").failed:
            print("MySQL install failed!")
        else:
            print("MySQL install success!")
    else:
        print("MySQL install not started on: " + env.host_string + "!")


def mysql_start():
    with settings(warn_only=True):
        if confirm("Start MySQL server on: " + env.host_string, default=False) == True:
            if sudo("systemctl start mysql").failed:
                print("MySQL server failed to start!")
                chown("/var/lib/mysql","mysql")
                mysql_start()
            else:
                print("MySQL server started successfully!")
        else:
            print("MySQL server not started on: " + env.host_string + "!")

def mysql_stop():
    with settings(warn_only=True):
        if confirm("Stopping MySQL server on: " + env.host_string, default=False) == True:
            if sudo("systemctl stop mysql").failed:
                print("MySQL server failed to stop!")
            else:
                print("MySQL server stopped successfully!")
        else:
            print("MySQL server not stopped on: " + env.host_string + "!")

def mysql_secure():
    if confirm("Run MySQL secure script on: " + env.host_string, default=False) == True:
        if sudo("/usr/bin/mysql_secure_installation").failed:
            print("MySQL secure script failed!")
        else:
            print("MySQL secure script success!")
    else:
        print("MySQL secure script not started on: " + env.host_string + "!")


def innodb_check():
    mysql_output = run('mysql -u{} -p{} -N -B -e "SELECT support FROM information_schema.engines WHERE engine = \'InnoDB\'"'.format(env.mysql_user,env.mysql_password))
    if mysql_output == "YES":
        print("InnoDB enabled!!")
    else:
        print("InnoDB failed!!")
        abort("Cloudera Manager Requires InnoDB to be active!!  Re-install MySQL DB!!")



def mysql_cm_create(db_name,user_name,pass_wd):
    mysql_db_create(db_name)
    mysql_user_create(db_name,user_name,pass_wd)

def mysql_db_create(db_name):
    if confirm("Create MySQL DB: " + db_name + " ?", default=False) == True:
        run('mysql -u{} -p{} -e "CREATE DATABASE {} DEFAULT CHARACTER SET utf8;"'.format(env.mysql_user,env.mysql_password,db_name))

def mysql_user_grant(db_name,user_name,pass_wd, grant_flag):
    if grant_flag == 'Y':
        grant_option = "WITH GRANT OPTION"
    else:
        grant_option = ""
    if confirm("Grant Access on " + db_name + " to " + user_name + " ?", default=False) == True:
        run('mysql -u{} -p{} -e "GRANT ALL ON {}.* TO \'{}\'@\'%\' IDENTIFIED BY \'{}\' {};"'.format(env.mysql_user,env.mysql_password,db_name,user_name,pass_wd,grant_option))

def mysql_user_create(db_name,user_name,pass_wd):
    if confirm("create user " + user_name + " ?", default=False) == True:
        run('mysql -u{} -p{} -e "CREATE USER \'{}\'@\'%\' IDENTIFIED BY \'{}\';"'.format(env.mysql_user,env.mysql_password,user_name,pass_wd))
    mysql_user_grant(db_name,user_name,pass_wd,"N")

def mysql_user_remove(user_name):
    if confirm("Remove MySQL user " + user_name + " ?", default=False) == True:
        run('mysql -u{} -p{} -e "DROP USER \'{}\'@\'%\';"'.format(env.mysql_user,env.mysql_password,user_name))

def mysql_db_remove(db_name):
    if confirm("Remove MySQL DB " + db_name + " ?", default=False) == True:
        run('mysql -u{} -p{} -e "DROP DATABASE {};"'.format(env.mysql_user,env.mysql_password,db_name))

def cm_prepare_db(ip_adr,user_name,pass_wd):
    if confirm("Prepare MySQL database for Cloudera Manager Server on: " + ip_adr + " ?", default=False) == True:
        sudo("/usr/share/cmf/schema/scm_prepare_database.sh mysql -h {} -u{} -p{} --scm-host {} scm scm scm".format(ip_adr,user_name,pass_wd,ip_adr))

@roles("namenode")
def install_wget():
        yum_install("wget")             #Installing wget to get CM repositories
        yum_install("createrepo")
        yum_install("httpd")            #Installing the web server for repo's
        service_start("httpd")          #Starting the web server for repo's 
        sudo("systemctl enable httpd.service")

@roles("namenode")
def download_mysql_package():
    with settings(warn_only=True):
        if confirm("Downloading RPM for MariaDB?", default=False) == True: 
            mkdir("/var/www/html/MariaDB")     #Creating repo directory for MariaDB
            mkdir("/var/www/html/MariaDB/rpms")     
            wget_dir(env.mariadb_baseurl,"/var/www/html/MariaDB/rpms")   #Getting MariaDB parcels from archive URL
            mkdir("/var/www/html/MariaDB/jdbc")     #Creating repo directory for MariaDB
            wget(env.mariadb_jdbc,"/var/www/html/MariaDB/jdbc")   #Getting MariaDB parcels from archive URL

@roles("cluster")
def install_mysql():
    jdbc_tarball = env.mariadb_jdbc.split('/')[-1]
    jdbc_name = jdbc_tarball.replace('.tar.gz','')
    if confirm("Installing mysql-connector-java?", default=False) == True:
        wget(env.mariadb_baseurl_local + "jdbc/" + jdbc_tarball,"~")
        sudo("mkdir -p /usr/share/java")
        sudo("tar zxf ~/" + jdbc_tarball + " -C /usr/share/java/ " + jdbc_name + "/" + jdbc_name + "-bin.jar")
        sudo("rm -f /usr/share/java/mysql-connector-java.jar")
        sudo("ln -s /usr/share/java/" + jdbc_name + "/" + jdbc_name + "-bin.jar /usr/share/java/mysql-connector-java.jar")


    if confirm("Installing MySQL server for Cloudera Manager?", default=False) == True:
        sudo('rm -rf /var/www/html/MariaDB/repodata')
        sudo('createrepo -p -d -o /var/www/html/MariaDB /var/www/html/MariaDB')
        sudo('echo "[mariadb]\nname = MariaDB\nbaseurl ={}\nenable = true\ngpgcheck = false\n" > /etc/yum.repos.d/mariadb.repo'.format(env.mariadb_baseurl_local))  #create new yum repo
        sudo('yum clean all') 
        yum_remove("mariadb-libs")
        #yum_install("libaio perl perl-DBI perl-Module-Pluggable perl-Pod-Escapes perl-Pod-Simple perl-libs perl-version")
        yum_install("MariaDB-server MariaDB-client")  
        #file_upload(env.config_local + "/my.cnf","/etc")    #Copy my.cnf text file for InnoDB config to remote server(s).
        chmod("/etc/my.cnf","644")      #Change mode of my.cnf to mysql user to 644.
        mysql_install()                 #Install the MySQL instance with the new my.cnf file.
        mysql_start()                   #Start the MySQL instance with the new my.cnf file.
        mysql_secure()                  #Running the secure script to set root password and remove unwanted settings.
        #innodb_check()                  #Checking that InnoDB enging is running on the newly installed MySQL server.
        
        mysql_user_grant("*",env.mysql_user,env.mysql_password, "Y")
        #mysql_cm_create("amon","amon","amon_password")
        mysql_cm_create("rman","rman","rman_password")
        mysql_cm_create("metastore","hive","hive_password")
        mysql_cm_create("sentry","sentry","sentry_password")
        mysql_cm_create("nav","nav","nav_password")
        mysql_cm_create("navms","navms","navms_password")
        mysql_cm_create("oozie","oozie","oozie_password")
        mysql_cm_create("hue","hue","hue_password")
        
    elif confirm("Installing MySQL Client only?", default=False) == True:
        sudo('echo "[mariadb]\nname = MariaDB\nbaseurl ={}\nenable = true\ngpgcheck = false\n" > /etc/yum.repos.d/mariadb.repo'.format(env.mariadb_baseurl_local))    #create new yum repo
        yum_install("MariaDB-client")

    elif confirm("Uninstall MySQL server and settings?", default=False) == True:
        mysql_stop()                    #Stop the running MySQL instance.
        yum_remove("MariaDB-server MariaDB-client")             #Remove MySQL on Nodes Past as variables in script call.
        rm_dir("/var/lib/mysql")        #Removing system files in preparation for a fresh build. 

    elif confirm("Uninstall MySQL client and settings?", default=False) == True:
        yum_remove("MariaDB-server MariaDB-client")
        rm_dir("/var/lib/mysql")        #Removing system files in preparation for a fresh build. 

    else:
        print("Nothing for MySQL required, moving on to Repository creation.")



def service_start(service_name):
    with settings(warn_only=True):
        if confirm("Start service " + service_name + " on server: " + env.host_string, default=False) == True:
            if sudo("systemctl start {}.service".format(service_name)).failed:
                print(service_name + " failed to start!")
            else:
                print(service_name + " started successfully!")
        else:
            print(service_name + " service not started on: " + env.host_string + "!")

def service_stop(service_name):
    with settings(warn_only=True):
        if confirm("Stop service " + service_name + " on server: " + env.host_string, default=False) == True:
            if sudo("systemctl stop {}.service".format(service_name)).failed:
                print(service_name + " failed to stop!")
            else:
                print(service_name + " stoped successfully!")
        else:
            print(service_name + " service not stoped on: " + env.host_string + "!")

def wget(source_path,target_path):
    if confirm("WGET file " + source_path + " into: " + target_path, default=False) == True:
        if sudo("wget {} -P {}".format(source_path,target_path)).failed:
            print(source_path + " failed to retrieve!")
        else:
            print(source_path + " successfully retrieved!")
    else:
        print(source_path + " not started on: " + env.host_string + "!")

def wget_dir(source_path,target_path):
    if confirm("WGET Directory " + source_path + " into: " + target_path, default=False) == True:
        if sudo("wget -c -r -nd -np -k -L -A rpm {} -P {}".format(source_path,target_path)).failed:
            print(source_path + " failed to retrieve!")
        else:
            print(source_path + " successfully retrieved!")
    else:
        print(source_path + " not started on: " + env.host_string + "!")

def download_parcel_package(package_name,parcel_url):
    if confirm("Downloading parcel for " + package_name + "?", default=False) == True:
        mkdir("/var/www/html/" + package_name) 
        wget(parcel_url,"/var/www/html/" + package_name)
        if(package_name == "anaconda"):
            wget(parcel_url + ".sha","/var/www/html/" + package_name)
        else:
            wget(parcel_url + ".sha1","/var/www/html/" + package_name)
          
def download_csd_package(package_name,csd_url):
    if confirm("Downloading CSD for " + package_name + "?", default=False) == True:
        wget(csd_url,"/var/www/html/" + package_name)
        
     
@roles("namenode")
def download_cm_package():
    if confirm("Downloading RPM for Cloudera Manager?", default=False) == True:
        mkdir("/var/www/html/cm5")     #Creating repo directory for Cloudera Manager
        wget_dir(env.cm_baseurl,"/var/www/html/cm5/")   #Getting CM parcels from cloudera.com archive
    if confirm("Downloading jdk1.80?", default=False) == True:         
         wget(env.jdk18_baseurl,"/var/www/html/cm5/")
    if confirm("Downloading JCE8?", default=False) == True:
        jce8_zip = env.jce8_baseurl.split('/')[-1]
        sudo("curl -v -j -k -L -O -H \"Cookie: oraclelicense=accept-securebackup-cookie\" " + env.jce8_baseurl)
        sudo("mv ~/" + jce8_zip + " /var/www/html/cm5/")

@roles("namenode")
def install_cm():
    if confirm("Install Cloudera Manager?", default=False) == True:
        sudo('rm -rf /var/www/html/cm5/repodata')
        sudo('createrepo -p -d -o /var/www/html/cm5 /var/www/html/cm5')
        sudo('echo "[cloudera-manager]\nname=cloudera manager\nbaseurl={}\nenable=true\ngpgcheck=false\n" > /etc/yum.repos.d/cloudera-manager.repo'.format(env.cm_baseurl_local))  #create new yum repo
        sudo('yum clean all')
        yum_install("oracle-j2sdk1.7")                     #Installing oracle-j2sdk1.7 for CM
        yum_install("cloudera-manager-daemons")            #Installing CM Daemons
        yum_install("cloudera-manager-server")             #Installing CM Server   
        cm_prepare_db(env.host_string,env.mysql_user,env.mysql_password)      #Passing parameters to the CM prepare DB script.    
        service_start("cloudera-scm-server")               #Start the Cloudera Manager Server.
    else:
        if confirm("Uninstall Cloudera Manager?", default=False) == True:
            service_stop("cloudera-scm-server")                #Stopping the CM server.
        
            yum_remove("oracle-j2sdk1.7")                      #Removing oracle-j2sdk1.7 for CM.
            yum_remove("cloudera-manager-daemons")             #Removing CM Daemons.
            yum_remove("cloudera-manager-server")              #Removing CM Server.
        
            rm_file("/etc/yum.repos.d/cloudera-manager.repo")  #Removing the repo file from the yum repository.
        else:
            print("Nothing for Cloudera Manager required, moving on to Kerberos step.")


def install_csd(package_name,csd_url,csd_url_local):
    if confirm("Install " + package_name + " CSD?", default=False) == True:
        csd_jar = csd_url.split('/')[-1]
        wget(csd_url_local + csd_jar,"/opt/cloudera/csd/")
        chmod("/opt/cloudera/csd/" + csd_jar,"644")
        chown("/opt/cloudera/csd/" + csd_jar,"cloudera-scm")
        service_stop("cloudera-scm-server")
        service_start("cloudera-scm-server")
        
       
@roles("namenode")
def download_other_package():
    download_parcel_package("cdh5",env.cdh_parcel)
    download_parcel_package("kafka",env.kafka_parcel)
    download_parcel_package("kudu",env.kudu_parcel)
    download_parcel_package("spark2",env.spark_parcel)
    download_parcel_package("cdsw",env.cdsw_parcel)
    download_parcel_package("anaconda",env.anaconda_parcel)
    download_csd_package("spark2",env.spark_csd)
    download_csd_package("cdsw",env.cdsw_csd)
    
@roles("namenode")
def install_csd_first():
    #install_csd("spark2",env.spark_csd,env.spark_baseurl_local)  
    install_csd("cdsw",env.cdsw_csd,env.cdsw_baseurl_local)

def kerb_db_install():
    if confirm("Create Database for Kerberos on: {}".format(env.host_string), default=False) == True:
        if sudo("/usr/sbin/kdb5_util create -s").failed:
            print("Kerberos DB install failed!")
        else:
            print("Kerberos DB install success!")
    else:
        print("Kerberos DB install not started on: {}!".format(env.host_string))

def first_principal(admin_acct):
    if confirm("Create first principal {} on: {}".format(admin_acct,env.host_string), default=False) == True:
        if sudo('/usr/sbin/kadmin.local -q "addprinc {}/admin"'.format(admin_acct)).failed:
            print("Kerberos first principal creation failed!")
        else:
            print("Kerberos first principal creation success!")
    else:
        print("Kerberos first principal install not started on: {}!".format(env.host_string))

def start_kerberos():
    if confirm("Start kerberos agents on: {}?".format(env.host_string), default=False) == True:
        service_start("krb5kdc")
        service_start("kadmin")
        sudo("systemctl enable krb5kdc.service")
        sudo("systemctl enable kadmin.service")
        
    else:
        print("Kerberos agents will not started on: {}!".format(env.host_string))

def stop_kerberos():
    if confirm("Stop kerberos agents on: {}?".format(env.host_string), default=False) == True:
        service_stop("krb5kdc")
        service_stop("kadmin")
    else:
        print("Kerberos agents will not stopped on: {}!".format(env.host_string))

@roles("cdsw")
def install_kerberos():
    if confirm("Install Kerberos Server on {}?".format(env.host_string), default=False) == True:
        yum_install("krb5-workstation")                #Installing krb5-workstation for Kerberos Client
        yum_install("krb5-server")                         #Installing krb5-server for Kerberos Authentication
        yum_install("krb5-libs")                           #Installing krb5-libs for Kerberos Authentication
        yum_install("krb5-auth-dialog")                    #Installing krb5-auth-dialog for Kerberos Authentication
        yum_install("openldap-clients")                    #Installing openldap-clients for Kerberos and AD (active directory)

        replace("/etc/krb5.conf","EXAMPLE.COM","{}".format(env.realm_string))
        replace("/etc/krb5.conf","kerberos.example.com","{}".format(env.host_string))
        replace("/etc/krb5.conf","example.com","{}".format(env.realm_string.lower()))
        append("/etc/krb5.conf","forwardable","default_tkt_enctypes = arcfour-hmac")
        append("/etc/krb5.conf","forwardable","default_tgs_enctypes = arcfour-hmac")
        append("/etc/krb5.conf","forwardable","udp_preference_limit = 1")

        replace("/var/kerberos/krb5kdc/kadm5.acl","EXAMPLE.COM","{}".format(env.realm_string))
        append("/var/kerberos/krb5kdc/kadm5.acl","admin@","cloudera-scm@{} admilc".format(env.realm_string))

        replace("/var/kerberos/krb5kdc/kdc.conf","EXAMPLE.COM","{}".format(env.realm_string))
        append("/var/kerberos/krb5kdc/kdc.conf","dict_file","max_file = 1d")
        append("/var/kerberos/krb5kdc/kdc.conf","dict_file","max_renewable_life = 7d")
        append("/var/kerberos/krb5kdc/kdc.conf","supported_enctypes","default_principal_flags = +renewable, +forwardable")
        kerb_db_install()

        first_principal("{}".format(env.princ_string))

        start_kerberos()

        file_download("/etc/krb5.conf",env.config_local)

    elif confirm("Install Kerberos Client on {}?".format(env.host_string), default=False) == True:

        yum_install("krb5-workstation")                #Installing krb5-workstation for Kerberos Client
        yum_install("krb5-libs")                       #Installing krb5-libs for Kerberos Authentication

        file_upload(env.config_local + "/krb5.conf","/etc")
        chmod("/etc/krb5.conf","644")      #Change mode of krb5.conf to mysql user to 644.

    elif confirm("Uninstall Kerberos on {}?".format(env.host_string), default=False) == True:
        stop_kerberos()
        yum_remove("krb5-server")                      #Removing krb5-server for CM.
        yum_remove("krb5-libs")                        #Removing krb5-libs for Kerberos Authentication for CM
        yum_remove("krb5-auth-dialog")                 #Removing krb5-auth-dialog for Kerberos Authentication.
        yum_remove("krb5-workstation")                 #Removing krb5-workstation.
        yum_remove("openldap-clients")                 #Removing open ldap.
    else:
        print("Nothing for Kerberos installed.")


def install_ad():
    if confirm("Install Kerberos on CM host {}?".format(env.host_string), default=False) == True:
        yum_install("krb5-workstation")                #Installing krb5-workstation for Kerberos Client
        yum_install("krb5-libs")                           #Installing krb5-libs for Kerberos Authentication
        yum_install("openldap-clients")                    #Installing openldap-clients for Kerberos and AD (active directory)

        replace("/etc/krb5.conf","EXAMPLE.COM","{}".format(env.realm_string))
        replace("/etc/krb5.conf","kerberos.example.com","{}".format(env.host_string))
        replace("/etc/krb5.conf","example.com","{}".format(env.realm_string.lower()))
        append("/etc/krb5.conf","forwardable","default_tkt_enctypes = arcfour-hmac")
        append("/etc/krb5.conf","forwardable","default_tgs_enctypes = arcfour-hmac")
        append("/etc/krb5.conf","forwardable","udp_preference_limit = 1")

        file_download("/etc/krb5.conf",env.config_local)
    elif confirm("Install Kerberos Client on {}?".format(env.host_string), default=False) == True:

        yum_install("krb5-workstation")                #Installing krb5-workstation for Kerberos Client
        yum_install("krb5-libs")                       #Installing krb5-libs for Kerberos Authentication

        file_upload(env.config_local + "/krb5.conf","/etc")
        chmod("/etc/krb5.conf","644")      #Change mode of krb5.conf to mysql user to 644.

    elif confirm("Uninstall Kerberos on {}?".format(env.host_string), default=False) == True:
        stop_kerberos()
        yum_remove("krb5-server")                      #Removing krb5-server for CM.
        yum_remove("krb5-libs")                        #Removing krb5-libs for Kerberos Authentication for CM
        yum_remove("krb5-auth-dialog")                 #Removing krb5-auth-dialog for Kerberos Authentication.
        yum_remove("krb5-workstation")                 #Removing krb5-workstation.
        yum_remove("openldap-clients")                 #Removing open ldap.
    else:
        print("Nothing for Kerberos installed.")

@roles("cluster")
def upgrade_java8():
    
    JAVA_HOME = "/usr/java/jdk1.8.0_121-cloudera"
    JCE_ZIP = "jce_policy-8.zip"
    
    if confirm("Upgrade jdk version to V1.8.0 on {}?".format(env.host_string), default=False) == True:
        yum_remove("oracle-j2sdk1.7")
        yum_install("oracle-j2sdk1.8")
        sudo("alternatives --install /usr/bin/java java " + JAVA_HOME + "/bin/java 10")
        sudo("alternatives --install /usr/bin/javac javac " + JAVA_HOME + "/bin/javac 10")
        sudo("ln -nfs " + JAVA_HOME + " /usr/java/latest")
        sudo("ln -nfs /usr/java/latest /usr/java/default")
    if confirm("Upgrade jce version to V8.0 on {}?".format(env.host_string), default=False) == True:    
        wget(env.cm_baseurl_local + JCE_ZIP,"~")
        sudo("unzip -o -j -d " + JAVA_HOME + "/jre/lib/security  ~/" + JCE_ZIP)

        
def hue_user_create(user_name,group_name):
    if confirm("Create hue user: \"" + user_name + "\" which belong to group: \"" + group_name + "\"?", default=False) == True:       
        with settings(warn_only=True):
            sudo("userdel -r " + user_name)
            sudo("groupadd "+ group_name)
        sudo("useradd -s /bin/bash -g " + group_name + " -m " + user_name)
        sudo("echo cloudera | sudo passwd --stdin " + user_name)
        #sudo("usermod -aG supergroup " + user_name)
        #sudo("usermod -aG wheel " + user_name)
        with settings(warn_only=True):
            sudo("sudo -u hdfs hadoop fs -mkdir /user/" + user_name)      
            sudo("sudo -u hdfs hadoop fs -chown -R " + user_name + ":" + group_name + " /user/" + user_name)

@roles("cluster")
def demo_user_create():
    #hue_user_create("feng","supergroup")        
    hue_user_create("test1","test1") 

@roles("cluster")
def test():
    yum_remove("jdk-1.6.0_31")
    


def cdh5_main():
#   service_start("rpcbind")                           #Start the RPCBind service to allow for NFS Gateway.
#   service_stop("rpcbind")                            #Stop the RPCBind service to allow for NFS Gateway.
    install_wget()

    download_mysql_package()
    
    download_cm_package()
    
    download_other_package()

    ntp()

    ip_tables()

    swappiness()

    nscd()

    selinux()

    THP()

    max_open_files()
        
    install_mysql()

    install_cm()

    install_kerberos()
    
    upgrade_java8()
           


    disconnect_all()



