%global commit0 2137ef08354e46499d34f95cde2654523065321d
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})

Name:           journal2lumberjack
Version:        0.0.0
Release:        0.5.git%{shortcommit0}%{?dist}
Summary:        Reads logs from the systemd Journal and forwards them remotely using the lumberjack protocol

License:        ASL 2.0
URL:            https://github.com/abokth/%{name}/
Source0:        https://github.com/abokth/%{name}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz

BuildRequires: systemd-devel
BuildRequires: zlib-devel
BuildRequires: inotify-tools-devel
BuildRequires: nspr-devel
BuildRequires: nss-util-devel
BuildRequires: nss-devel
Requires: socat

Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: systemd

Requires(pre): shadow-utils

%description
Reads logs from the systemd Journal and forwards them remotely using the lumberjack protocol.

%prep
%setup -qn %{name}-%{commit0}

%build
make CFLAGS="%{optflags}" %{?_smp_mflags} -C src

cat >%{name}.environment <<'EOF'
#DESTINATION_HOST=servername
#DESTINATION_PORT=portnumber
EOF

cat >tmpfiles.conf <<'EOF'
d /run/journal2lumberjack 0755 journal2lumberjack journal2lumberjack -
EOF

%install
rm -rf $RPM_BUILD_ROOT
%{__install} -p -D -m0644 %{name}.environment $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/%{name}
%{__install} -p -D -m0644 src/%{name}.service $RPM_BUILD_ROOT%{_prefix}/lib/systemd/system/%{name}.service

%{__mkdir} -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/%{name}

%{__install} -p -D -m0755 src/%{name} $RPM_BUILD_ROOT%{_libexecdir}/%{name}

%{__mkdir} -p $RPM_BUILD_ROOT%{_tmpfilesdir}
%{__install} -m 0644 tmpfiles.conf $RPM_BUILD_ROOT%{_tmpfilesdir}/%{name}.conf

%{__mkdir} -p $RPM_BUILD_ROOT/run
%{__install} -d -m 0755 $RPM_BUILD_ROOT/run/%{name}/

%{__mkdir} -p $RPM_BUILD_ROOT%{_localstatedir}/lib
%{__install} -d -m 0755 $RPM_BUILD_ROOT%{_localstatedir}/lib/%{name}/

%pre
getent group %{name} >/dev/null || groupadd -r %{name} || :
getent passwd %{name} >/dev/null || \
    useradd -r -g %{name} -d %{_localstatedir}/lib/%{name} -s /sbin/nologin \
    -c "The %{name} daemon" %{name} || :

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service 


%files
%doc README.md
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%dir %{_sysconfdir}/pki/%{name}
%{_prefix}/lib/systemd/system/%{name}.service
%{_libexecdir}/%{name}
%{_tmpfilesdir}/%{name}.conf
%dir %attr(0755, %{name}, %{name}) /run/%{name}/
%dir %attr(0755, %{name}, %{name}) %{_localstatedir}/lib/%{name}

%changelog
* Fri Oct  2 2015 Alexander Boström - 0.0-0.5.git2137ef0
- Initial build.
