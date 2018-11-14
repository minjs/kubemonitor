Summary:            A program that ejects removable media using software control
Name:               zs-agent
Version:            0.1.0
Release:            21%{?dist}
License:            GPLv2+
Source:             %{name}-%{version}.tar.gz
URL:
ExcludeArch:

%description

%prep
%autosetup -n %{name}

%build
%configure
%make_build

%install
%make_install

install -m 755 -d %{buildroot}/%{_sbindir}
ln -s ../bin/eject %{buildroot}/%{_sbindir}

%find_lang %{name}

%files -f %{name}.lang
%license
%doc
%{_bindir}/*
%{_sbindir}/*
%{_mandir}/man1/*

%changelog
