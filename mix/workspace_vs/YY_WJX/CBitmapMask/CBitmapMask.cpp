#include "CBitmapMask.h"

CBitmapMask::CBitmapMask(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	connect(ui.pushButton, SIGNAL(clicked()), this , SLOT(ShowBmp()));
	m_pLabel = new QLabel(ui.centralWidget);
	m_pLabel->setGeometry(40,40,100,100);
}

CBitmapMask::~CBitmapMask()
{

}

void CBitmapMask::ShowBmp()
{
	QPixmap pmp("pic/a/LOGO.bmp");
	QBitmap msk("pic/b/LOGO.bmp");
	pmp.setMask(msk);
	m_pLabel->setPixmap(pmp);
    //m_pLabel->setMask(msk);
}