mkdir -p ./rpmbuild/SPRMS
mkdir -p ./rpmbuild/SOURCES
mkdir -p ./rpmbuild/SPECS
mkdir -p ./rpmbuild/tmp

#cat <<EOF >.rpmmacros
#%_topdir   $(echo )/rpmbuild
#%_tmppath  %{_topdir}/tmp
#EOF

cat <<EOF > zsAgent.service
[Unit]
Description=Zero Systems Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/zero_agent/zsAgent -controller $1 -int $2
Restart=on-abort
TimeoutStopSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
make

cd rpmbuild

mkdir -p zsAgent-1.0/usr/bin/zero_agent
mkdir -p zsAgent-1.0/etc/systemd/system

install -m 755 ../agent zsAgent-1.0/usr/bin/zero_agent/zsAgent
install -m 755 ../namespace_mgmt/run_svc_in_ns.sh zsAgent-1.0/usr/bin/zero_agent/ns.sh
install -m 755 ../zsAgent.service zsAgent-1.0/etc/systemd/system/zsAgent.service

tar -zcvf zsAgent-1.0.tar.gz zsAgent-1.0/

cp ./zsAgent-1.0.tar.gz ./SOURCES/zsAgent-1.0.tar.gz

cat <<EOF > SPECS/zsAgent.spec
# Don't try fancy stuff like debuginfo, which is useless on binary-only
# packages. Don't strip binary too
# Be sure buildpolicy set to do nothing
%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress

Summary: Zero Systems Agent rpm package
Name: zsAgent
Version: 1.0
Release: 1
License: http://www.zerosystems.io/license
Group: Development/Tools
SOURCE0 : %{name}-%{version}.tar.gz
URL: http://www.zerosystems.io/

BuildRoot: ./rpmbuild/tmp/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%build
# Empty section.

%install
rm -rf %{buildroot}
mkdir -p  %{buildroot}

# in builddir
cp -a * %{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
#%config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
/etc/systemd/system/zsAgent.service
%{_bindir}/*

%changelog
* Wed Aug 30 2017  Zero Systems <build@zerosystems.io> 1.0-1
- First Build

EOF
rpmbuild --define '_topdir '`pwd` -ba ./SPECS/zsAgent.spec
cd ..
cp ./rpmbuild/RPMS/x86_64/zsAgent-1.0-1.x86_64.rpm ./
chmod +x ./agent