/****************************************************************************
** Meta object code from reading C++ file 'CInbox.h'
**
** Created: Fri Jun 24 10:53:04 2011
**      by: The Qt Meta Object Compiler version 62 (Qt 4.6.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "CInbox.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CInbox.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 62
#error "This file was generated using the moc from 4.6.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CInbox[] = {

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
       8,    7,    7,    7, 0x0a,
      29,   24,    7,    7, 0x0a,
      65,    7,    7,    7, 0x0a,
      87,    7,    7,    7, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CInbox[] = {
    "CInbox\0\0SlotAddNewMsg()\0item\0"
    "SlotItemActivated(QListWidgetItem*)\0"
    "SetInformation(void*)\0NoticeCtrl(void*)\0"
};

const QMetaObject CInbox::staticMetaObject = {
    { &QMainWindow::staticMetaObject, qt_meta_stringdata_CInbox,
      qt_meta_data_CInbox, 0 }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CInbox::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CInbox::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CInbox::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CInbox))
        return static_cast<void*>(const_cast< CInbox*>(this));
    return QMainWindow::qt_metacast(_clname);
}

int CInbox::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: SlotAddNewMsg(); break;
        case 1: SlotItemActivated((*reinterpret_cast< QListWidgetItem*(*)>(_a[1]))); break;
        case 2: SetInformation((*reinterpret_cast< void*(*)>(_a[1]))); break;
        case 3: NoticeCtrl((*reinterpret_cast< void*(*)>(_a[1]))); break;
        default: ;
        }
        _id -= 4;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
