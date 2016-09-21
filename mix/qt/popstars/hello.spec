Summary:xikang
Name:hello
Version:0.1.26
Release:3.0.xikang

Group:xikang-app
License:commercial
Source:hello.tar.gz	



%description
xikang NetRadio help

%prep
rm -rf $RPM_BUILD_ROOT

%build

%install
cd  $ACORN_DEVEL_ROOT/Application/hello

install -d $RPM_BUILD_ROOT/usr/local/acorn/app/bin
install -d $RPM_BUILD_ROOT/usr/local/acorn/app/desktop
install -d $RPM_BUILD_ROOT/usr/local/acorn/app/res
install -d $RPM_BUILD_ROOT/usr/local/acorn/app/hello


cp -af hello $RPM_BUILD_ROOT/usr/local/acorn/app/hello
cp -af desktop/hello.desktop $RPM_BUILD_ROOT/usr/local/acorn/app/desktop

cp -af hello_*.png  $RPM_BUILD_ROOT/usr/local/acorn/app/res/
cp -af hello.lnk $RPM_BUILD_ROOT/usr/local/acorn/app/bin/

%post

%files
 /usr/local/acorn/app/hello/hello
    /usr/local/acorn/app/bin/hello.lnk
   /usr/local/acorn/app/desktop/hello.desktop
   /usr/local/acorn/app/res/hello_1.png
   /usr/local/acorn/app/res/hello_2.png
   /usr/local/acorn/app/res/hello_3.png

   
%changelog
