#include <QtGui/QApplication>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QDir>
#include <QTime>




bool TraverseGetLastFile(QString & filename, QDateTime & time)
{
	if(QFileInfo(filename).isDir())
	{
		QDir dir(filename);

		QString tempFilename = filename;
		QDateTime tempTime = time;

		QList<QFileInfo> list = dir.entryInfoList();

		for(int i = 0; i < list.count(); i++)
		{
			QString str = list.at(i).fileName();
			if(str == "." || str == "..")
			{
				continue ;
			}

			tempFilename = list.at(i).absoluteFilePath();
			TraverseGetLastFile(tempFilename, tempTime);

			if(tempTime > time)
			{
				filename = tempFilename;
				time = tempTime;
			}
		}
	}
	else
	{
		if(filename.contains(".c") && !filename.contains(".cfg"))
		{
			QFile file("file.log");

			file.open(QIODevice::Append);

			file.write("LOCAL_SRC_FILES += ");

			file.write(filename.remove("C:/Users/Administrator/Desktop/filea/Test4O_All/O_All/").toAscii());

			file.write("\n");


			file.close();
		}

	}
	return true;
}



int main(int argc, char *argv[])
{
	//QString str("C:/Users/Administrator/Desktop/filea/Test4O_All/O_All");
	//QDateTime time;
	//TraverseGetLastFile(str, time);

	//QString strFlag("ANGLE_DX11 CHROMIUM_BUILD USE_LIBJPEG_TURBO=1 ENABLE_ONE_CLICK_SIGNIN ENABLE_REMOTING=1 ENABLE_WEBRTC=1 ENABLE_PEPPER_CDMS ENABLE_CONFIGURATION_POLICY ENABLE_INPUT_SPEECH ENABLE_NOTIFICATIONS ENABLE_HIDPI=1 ENABLE_GPU=1 ENABLE_EGLIMAGE=1 ENABLE_TASK_MANAGER=1 ENABLE_EXTENSIONS=1 ENABLE_PLUGIN_INSTALLATION=1 ENABLE_PLUGINS=1 ENABLE_SESSION_SERVICE=1 ENABLE_THEMES=1 ENABLE_AUTOFILL_DIALOG=1 ENABLE_BACKGROUND=1 ENABLE_AUTOMATION=1 ENABLE_GOOGLE_NOW=1 ENABLE_FULL_PRINTING=1 ENABLE_PRINTING=1 ENABLE_SPELLCHECK=1 ENABLE_CAPTIVE_PORTAL_DETECTION=1 ENABLE_APP_LIST=1 ENABLE_SETTINGS_APP=1 ENABLE_MANAGED_USERS=1 _NSPR_BUILD_ FORCE_PR_LOG XP_UNIX _PR_PTHREADS HAVE_DLADDR HAVE_LCHOWN HAVE_SOCKLEN_T HAVE_STRERROR NSPR_STATIC NDEBUG NVALGRIND DYNAMIC_ANNOTATIONS_ENABLED=0 MP_API_COMPATIBLE NSS_DISABLE_DBM NSS_ENABLE_ECC NSS_STATIC NSS_USE_STATIC_LIBS RIJNDAEL_INCLUDE_TABLES SHLIB_VERSION=\"3\" SOFTOKEN_SHLIB_VERSION=\"3\" USE_UTIL_DIRECTLY NSS_DISABLE_ROOT_CERTS NSS_DISABLE_LIBPKIX SHLIB_SUFFIX=\"dylib\" SHLIB_PREFIX=\"lib\" SOFTOKEN_LIB_NAME=\"libsoftokn3.dylib\" NO_NSPR_10_SUPPORT");

	//strFlag.replace("  "," ");

	//strFlag.replace(" ", " -D");

	//{
	//		QFile file("C_FLAGS.log");

	//		file.open(QIODevice::Append);


	//		file.write(strFlag.toAscii());



	//		file.close();
	//}


	QString strInclude("./nspr/pr/include/ ./nspr/lib/ds/ ./nspr/lib/libc/include/ ./nspr/pr/include/obsolete ./nss/lib/base ./nss/lib/certdb ./nss/lib/certhigh ./nss/lib/cryptohi ./nss/lib/dev ./nss/lib/freebl ./nss/lib/freebl/ecl ./nss/lib/freebl/mpi ./nss/lib/nss ./nss/lib/pk11wrap ./nss/lib/pkcs7 ./nss/lib/pki ./nss/lib/smime ./nss/lib/softoken ./nss/lib/ssl ./nss/lib/util ./nss/lib/ckfw ./nss/lib/pkcs12 /usr/include/libxml2");

	strInclude.replace("./","\nLOCAL_C_INCLUDES += $(LOCAL_PATH)/O_All/");

	{
			QFile file("C_include.log");

			file.open(QIODevice::Append);


			file.write(strInclude.toAscii());


			file.close();
	}

	return 0;
}
