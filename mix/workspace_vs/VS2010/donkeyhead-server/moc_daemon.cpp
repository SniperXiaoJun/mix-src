/****************************************************************************
** Meta object code from reading C++ file 'daemon.h'
**
** Created: Mon May 10 15:21:07 2010
**      by: The Qt Meta Object Compiler version 62 (Qt 4.6.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "daemon.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'daemon.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 62
#error "This file was generated using the moc from 4.6.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_Daemon[] = {

 // content:
       4,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
       8,    7,    7,    7, 0x08,
      32,    7,    7,    7, 0x08,
      63,    7,    7,    7, 0x08,
      85,    7,    7,    7, 0x08,

       0        // eod
};

static const char qt_meta_stringdata_Daemon[] = {
    "Daemon\0\0on_sendButton_clicked()\0"
    "on_startListenButton_clicked()\0"
    "on_about_Connection()\0on_read_Datagrams()\0"
};

const QMetaObject Daemon::staticMetaObject = {
    { &QMainWindow::staticMetaObject, qt_meta_stringdata_Daemon,
      qt_meta_data_Daemon, 0 }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &Daemon::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *Daemon::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *Daemon::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_Daemon))
        return static_cast<void*>(const_cast< Daemon*>(this));
    return QMainWindow::qt_metacast(_clname);
}

int Daemon::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: on_sendButton_clicked(); break;
        case 1: on_startListenButton_clicked(); break;
        case 2: on_about_Connection(); break;
        case 3: on_read_Datagrams(); break;
        default: ;
        }
        _id -= 4;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
