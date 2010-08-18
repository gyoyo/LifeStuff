/*
 * copyright maidsafe.net limited 2009
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: May 19, 2009
 *      Author: Team
 */

#include "qt/perpetual_data.h"

// qt
#include <QDebug>
#include <QTranslator>
#include <QMessageBox>
#include <QProcess>
#include <QList>
#include <QFileDialog>
#include <QInputDialog>
#include <boost/progress.hpp>
#include <QLibraryInfo>
#include <QDesktopWidget>
#include <QDesktopServices>
#include <QUrl>

#include <list>
#include <map>
#include <string>
#include <iostream>
#include <fstream>

// core
#include "qt/client/client_controller.h"

// local
#include "qt/widgets/login.h"
#include "qt/widgets/create_user.h"
#include "qt/widgets/progress.h"
#include "qt/widgets/user_panels.h"
#include "qt/widgets/system_tray_icon.h"
#include "qt/widgets/user_settings.h"
#include "qt/widgets/pending_operations_dialog.h"

#include "qt/client/create_user_thread.h"
#include "qt/client/join_kademlia_thread.h"
#include "qt/client/mount_thread.h"
#include "qt/client/save_session_thread.h"
#include "qt/client/user_space_filesystem.h"

// generated
#include "ui_about.h"

PerpetualData::PerpetualData(QWidget* parent)
    : QMainWindow(parent), quitting_(false), login_(NULL), create_(NULL),
      message_status_(NULL), state_(LOGIN) {
  setAttribute(Qt::WA_DeleteOnClose, false);
  setWindowIcon(QPixmap(":/icons/32/Triangle"));
  ui_.setupUi(this);

  statusBar()->show();
  statusBar()->addPermanentWidget(message_status_ = new QLabel);

  createActions();
  createMenus();
  showLoggedOutMenu();
  // create the main screens
  login_ = new Login;
  create_ = new CreateUser;
  progressPage_ = new Progress;
  userPanels_ = new UserPanels;

  ui_.stackedWidget->addWidget(login_);
  ui_.stackedWidget->addWidget(create_);
  ui_.stackedWidget->addWidget(progressPage_);
  ui_.stackedWidget->addWidget(userPanels_);

  setCentralWidget(ui_.stackedWidget);
  ui_.stackedWidget->setCurrentWidget(login_);

  JoinKademliaThread *jkt = new JoinKademliaThread(this);
  connect(jkt,  SIGNAL(completed(bool)),
          this, SLOT(onJoinKademliaCompleted(bool)));
  jkt->start();

  login_->StartProgressBar();

  qtTranslator = new QTranslator;
  myAppTranslator = new QTranslator;
  QString locale = QLocale::system().name().left(2);
  qtTranslator->load("qt_" + locale,
            QLibraryInfo::location(QLibraryInfo::TranslationsPath));
  qApp->installTranslator(qtTranslator);

  bool res = myAppTranslator->load(":/translations/pd_translation_" + locale);
  if (res) {
    qApp->installTranslator(myAppTranslator);
    ui_.retranslateUi(this);
  }
}

void PerpetualData::onJoinKademliaCompleted(bool b) {
  if (!b) {
    qDebug() << "U didn't join kademlia, so fuck U!";
    return;
  }
  login_->reset();
  qDebug() << "PerpetualData::onJoinKademliaCompleted";
  setState(LOGIN);

  connect(ClientController::instance(),
          SIGNAL(messageReceived(int,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)),
          this,
          SLOT(onMessageReceived(int,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)));

  connect(ClientController::instance(),
                SIGNAL(shareReceived(const QString&, const QString&)),
          this, SLOT(onShareReceived(const QString&, const QString&)));

  connect(ClientController::instance(),
                SIGNAL(fileReceived(const QString &sender,
                                    const QString &filename,
                                    const QString &tag, int sizeLow,
                                    int sizeHigh,
                                    const ClientController::ItemType &type)),
          this, SLOT(onFileReceived(const QString &sender,
                                    const QString &filename,
                                    const QString &tag, int sizeLow,
                                    int sizeHigh,
                                    const ClientController::ItemType &type)));

  connect(ClientController::instance(),
                SIGNAL(connectionStatusChanged(int)),
          this, SLOT(onConnectionStatusChanged(int)));

  connect(ClientController::instance(),
                SIGNAL(emailReceieved(const QString &subject,
                                      const QString &conversation,
                                      const QString &message,
                                      const QString &sender,
                                      const QString &date)),
           this, SLOT(onEmailReceived(const QString &subject,
                                      const QString &conversation,
                                      const QString &message,
                                      const QString &sender,
                                      const QString &date)));
}

PerpetualData::~PerpetualData() {
//  onLogout();
}

void PerpetualData::createActions() {
// most of the actions have already been created for the menubar
  actions_[ QUIT ] = ui_.actionQuit;
  actions_[ LOGOUT ] = ui_.actionLogout;
  actions_[ FULLSCREEN ] = ui_.actionFullScreen;
  actions_[ ABOUT ] = ui_.actionAbout;
  actions_[ PRIVATE_SHARES ] = ui_.actionPrivate_Shares;
  actions_[ GO_OFFLINE ] = ui_.actionOffline;
  actions_[ SETTINGS ] = ui_.actionSettings_2;
  actions_[ ONLINE ] = ui_.actionAvailable;
  actions_[ AWAY ] = ui_.actionAway;
  actions_[ BUSY ] = ui_.actionBusy;
  actions_[ OFFLINE_2 ] = ui_.actionOffline_2;
  //actions_[ EMAIL ] = ui_.actionEmail;
  actions_[ OFF ] = ui_.actionOff_2;
  actions_[ SMALL ] = ui_.actionSmall_2;
  actions_[ FULL ] = ui_.actionFull_2;
  actions_[ MANUAL ] = ui_.actionManual;
  actions_[ UPDATE ] = ui_.actionUpdate;
// actions_[ SAVE_SESSION ] = ui_.actionSave_Session;
  actions_[ THEME_BLUE ] = ui_.actionBlue;
  actions_[ THEME_BLACK ] = ui_.actionBlack;
  actions_[ THEME_RED ] = ui_.actionRed;
  actions_[ THEME_GREEN ] = ui_.actionGreen;

// Remove Status Menu until implemented
  ui_.menuStatus->setVisible(false);
  actions_[ ONLINE ]->setVisible(false);
  actions_[ AWAY ]->setVisible(false);
  actions_[ BUSY ]->setVisible(false);
  actions_[ OFFLINE_2 ]->setVisible(false);
  actions_[ QUIT ]->setShortcut(Qt::ALT + Qt::Key_F4);
  actions_[ FULLSCREEN ]->setShortcut(Qt::Key_F11);

  connect(actions_[ QUIT ], SIGNAL(triggered()),
          this,             SLOT(onQuit()));
  connect(actions_[ LOGOUT ], SIGNAL(triggered()),
          this,               SLOT(onLogout()));
  connect(actions_[ FULLSCREEN ], SIGNAL(toggled(bool)),
          this,              SLOT(onToggleFullScreen(bool)));
  connect(actions_[ ABOUT ], SIGNAL(triggered()),
          this,              SLOT(onAbout()));
  connect(actions_[ PRIVATE_SHARES ], SIGNAL(triggered()),
          this,                       SLOT(onPrivateShares()));
  connect(actions_[ GO_OFFLINE ], SIGNAL(toggled(bool)),
          this,                   SLOT(onGoOffline(bool)));
  connect(actions_[ SETTINGS ], SIGNAL(triggered()),
          this,                 SLOT(onSettingsTriggered()));
  connect(actions_[ ONLINE ], SIGNAL(triggered()),
          this,               SLOT(onOnlineTriggered()));
  connect(actions_[ AWAY ], SIGNAL(triggered()),
          this,             SLOT(onAwayTriggered()));
  connect(actions_[ BUSY ], SIGNAL(triggered()),
          this,             SLOT(onBusyTriggered()));
  connect(actions_[ OFFLINE_2 ], SIGNAL(triggered()),
          this,                  SLOT(onOffline_2Triggered()));
  //connect(actions_[ EMAIL ], SIGNAL(triggered()),
          //this,              SLOT(onEmailTriggered()));
// connect(actions_[ SAVE_SESSION ], SIGNAL(triggered()),
//         this,                     SLOT(onSaveSession()));
  connect(actions_[ OFF ], SIGNAL(triggered()),
          this,             SLOT(onOffTriggered()));
  connect(actions_[ SMALL ], SIGNAL(triggered()),
          this,                  SLOT(onSmallTriggered()));
  connect(actions_[ FULL ], SIGNAL(triggered()),
          this,              SLOT(onFullTriggered()));
  connect(actions_[ MANUAL ], SIGNAL(triggered()),
          this,              SLOT(onManualTriggered()));
  connect(actions_[ UPDATE ], SIGNAL(triggered()),
          this,              SLOT(onUpdateTriggered()));
  connect(actions_[ THEME_BLACK ], SIGNAL(triggered()),
          this,              SLOT(onBlackThemeTriggered()));
  connect(actions_[ THEME_BLUE ], SIGNAL(triggered()),
          this,              SLOT(onBlueThemeTriggered()));
  connect(actions_[ THEME_GREEN ], SIGNAL(triggered()),
          this,              SLOT(onGreenThemeTriggered()));
  connect(actions_[ THEME_RED ], SIGNAL(triggered()),
          this,              SLOT(onRedThemeTriggered()));
}

void PerpetualData::createMenus() {
#if defined(PD_WIN32)
  // an example of launching an extrernal application
  // path to application is stored in the action

  QAction* actionNotepad = new QAction(this);
  actionNotepad->setText(tr("Notepad"));
  actionNotepad->setData(QVariant("C:/Windows/System32/notepad.exe"));
  connect(actionNotepad, SIGNAL(triggered()),
           this,          SLOT(onApplicationActionTriggered()));

  ui_.menuApplications->addAction(actionNotepad);
#endif
}

void PerpetualData::setState(State state) {
  disconnect(login_, NULL, this, NULL);
  disconnect(create_, NULL, this, NULL);
  disconnect(progressPage_, NULL, this, NULL);
  disconnect(userPanels_, NULL, this, NULL);

  userPanels_->setActive(false);

  state_ = state;

  switch (state_) {
    case LOGIN:
    {
        ui_.stackedWidget->setCurrentWidget(login_);
        login_->clearFields();
        connect(login_, SIGNAL(newUser()),
                this,   SLOT(onLoginNewUser()));
        connect(login_, SIGNAL(existingUser()),
                this,   SLOT(onLoginExistingUser()));
        break;
    }
    case SETUP_USER:
    {
        create_->reset();
        ui_.stackedWidget->setCurrentWidget(create_);
        connect(create_, SIGNAL(complete()),
                this,    SLOT(onSetupNewUserComplete()));
        connect(create_, SIGNAL(cancelled()),
                this,    SLOT(onSetupNewUserCancelled()));
        break;
    }
    case CREATE_USER:
    {
        ui_.stackedWidget->setCurrentWidget(progressPage_);
        progressPage_->setTitle(tr("Creating User Account"));
        progressPage_->setProgressMessage(
            tr("A user account is being created. This may take some time..."));
        progressPage_->setError(false);
        progressPage_->setCanCancel(false);  // can't cancel it yet
        // connect(create_, SIGNAL(cancel()),
        //         this,    SLOT(onCreateCancelled()));
        break;
    }
    case MOUNT_USER:
    {
        ui_.stackedWidget->setCurrentWidget(progressPage_);
        progressPage_->setTitle(tr("Mounting User File System"));
        progressPage_->setProgressMessage(
            tr("Your file system is being set up..."));
        progressPage_->setError(false);
        progressPage_->setCanCancel(false);  // can't cancel it yet
        // connect(create_, SIGNAL(cancel()),
        //         this, SLOT(onMountCancelled()));
        break;
    }
    case LOGGED_IN:
    {
        showLoggedInMenu();
        ui_.stackedWidget->setCurrentWidget(userPanels_);
        connect(userPanels_, SIGNAL(unreadMessages(int)),
                this,        SLOT(onUnreadMessagesChanged(int)));
        connect(userPanels_, SIGNAL(publicUsernameChosen()),
                this,         SLOT(onPublicUsernameChosen()));
        userPanels_->setActive(true);
        break;
    }
    case LOGGING_OUT:
    {
        showLoggedOutMenu();
        ui_.stackedWidget->setCurrentWidget(progressPage_);
        progressPage_->setTitle(tr("Logging out"));
        progressPage_->setProgressMessage(
            tr("Logging out and removing all traces of you from the "
               "system..."));
        progressPage_->setError(false);
        progressPage_->setCanCancel(false);
        break;
    }
    case FAILURE:
    {
        ui_.stackedWidget->setCurrentWidget(progressPage_);
        progressPage_->setError(true);
        progressPage_->setCanCancel(false);
        connect(progressPage_, SIGNAL(ok()),
                this,          SLOT(onFailureAcknowledged()));
        break;
    }
    default:
    {
        break;
    }
  }

  if (state != LOGGED_IN) {
      message_status_->clear();
  }
}

void PerpetualData::onLoginExistingUser() {
  qDebug() << "onLoginExistingUser";
  // existing user whose credentials have been verified
  // mount the file system..

  qDebug() << "public name:" << ClientController::instance()->publicUsername();

#ifdef PD_LIGHT
  onMountCompleted(true);
#else
  setState(MOUNT_USER);
  asyncMount();
#endif
}

void PerpetualData::onLoginNewUser() {
  setState(SETUP_USER);
}

void PerpetualData::onSetupNewUserComplete() {
  qDebug() << "onSetupNewUserComplete";
  // user has been successfully setup. can go ahead and create them

  setState(CREATE_USER);
  asyncCreateUser();
}

void PerpetualData::onSetupNewUserCancelled() {
  // process was cancelled. back to login.
  setState(LOGIN);
}

void PerpetualData::asyncMount() {
  MountThread* mt = new MountThread(MountThread::MOUNT, this);
  connect(mt,   SIGNAL(completed(bool)),
          this, SLOT(onMountCompleted(bool)));

  mt->start();
}

void PerpetualData::asyncUnmount() {
  MountThread* mt = new MountThread(MountThread::UNMOUNT, this);
  connect(mt,   SIGNAL(completed(bool)),
          this, SLOT(onUnmountCompleted(bool)));

  mt->start();
}

//  void PerpetualData::asyncLogout() {
//    LogoutUserThread* lut = new LogoutUserThread();
//    connect(lut,   SIGNAL(logoutUserCompleted(bool)),
//           this, SLOT(onLogoutUserCompleted(bool)));
//
//    lut->start();
//  }

void PerpetualData::asyncCreateUser() {
  CreateUserThread* cut = new CreateUserThread(login_->username(),
                                               login_->pin(),
                                               login_->password(),
                                               create_->VaultType(),
                                               create_->SpaceOffered(),
                                               create_->PortChosen(),
                                               create_->DirectoryChosen(),
                                               this);
  create_->reset();
  connect(cut,  SIGNAL(completed(bool)),
          this, SLOT(onUserCreationCompleted(bool)));

  create_->reset();

  cut->start();
}

void PerpetualData::onUserCreationCompleted(bool success) {
  qDebug() << "PerpetualData::onUserCreationCompleted:" << success;

  if (success) {
#ifdef PD_LIGHT
  ClientController::instance()->SetMounted(0);
  onMountCompleted(true);
#else
  setState(MOUNT_USER);
  asyncMount();
#endif
  } else {
    progressPage_->setProgressMessage(tr("Failed creating a user account."));
    setState(FAILURE);
  }
}

void PerpetualData::onMountCompleted(bool success) {
  qDebug() << "PerpetualData::onMountCompleted: " << success;

  if (success) {
    const QString pu = ClientController::instance()->publicUsername();
    if (!pu.isEmpty()) {
      statusBar()->showMessage(tr("Logged in: %1").arg(pu));
    } else {
      statusBar()->showMessage(tr("Logged in"));
    }
    setState(LOGGED_IN);
    qDebug() << QString("Logged in: %1").arg(pu);
  } else {
    // TODO(Team#5#): 2009-08-18 - more detail about the failure
    progressPage_->setProgressMessage(
        tr("The file system could not be mounted."));
    setState(FAILURE);
  }
  if (!ClientController::instance()->publicUsername().isEmpty())
    ClientController::instance()->StartCheckingMessages();
}

void PerpetualData::onUnmountCompleted(bool success) {
  qDebug() << "PerpetualData::onUnMountCompleted: " << success;

  if (success) {
    // TODO(Team#5#): 2009-08-18 - disable the logout action
    statusBar()->showMessage(tr("Logged out"));

    if (!quitting_)
      setState(LOGIN);
  } else {
    // TODO(Team#5#): 2009-08-18 - more detail about the failure
    progressPage_->setProgressMessage(
        tr("The file system could not be unmounted."));
    setState(FAILURE);
  }

  if (quitting_) {
    // TODO(Team#5#): 2009-08-18 - what to do (or can we do)
    //                             if logout failed but we're closing
    //                             the application?
    ClientController::instance()->shutdown();
    qApp->quit();
  }
}

void PerpetualData::onSaveSessionCompleted(int result) {
  QString saveSessionMsg(tr("Your session could not be saved."));
  if (result == 0)
    saveSessionMsg = tr("Your session was successfully saved.");
  qDebug() << "PerpetualData::onSaveSessionCompleted - Result: " << result;

//  QMessageBox::warning(this, tr("Notification!"), saveSessionMsg);
  SystemTrayIcon::instance()->showMessage(tr("Alert"), saveSessionMsg);
}

void PerpetualData::onFailureAcknowledged() {
  setState(LOGIN);
}

void PerpetualData::onLogout() {
  if (state_ != LOGGED_IN) {
    // if we're still to login we can't logout
    return;
  }
  if (!ClientController::instance()->publicUsername().isEmpty())
    ClientController::instance()->StopCheckingMessages();
  asyncUnmount();
#ifdef PD_LIGHT
  userPanels_->CloseFileBrowser();
#endif

  setState(LOGGING_OUT);
}

void PerpetualData::quit() {
  showNormal();
  onQuit();
}

void PerpetualData::onQuit() {
  // TODO(Team#5#): 2009-08-18 - confirm quit if something in progress
  QList<ClientController::PendingOps> ops;

  if (ClientController::instance()->getPendingOps(ops)) {
    pendingOps_ = new PendingOperationsDialog;
  } else {
    if (state_ != LOGGED_IN) {
      ClientController::instance()->shutdown();
      qApp->quit();
    } else {
      quitting_ = true;
      onLogout();
    }
  }
}

void PerpetualData::onAbout() {
  QDialog about;
  Ui::About ui;
  ui.setupUi(&about);

  about.exec();
}

void PerpetualData::onMyFiles() {
  if (ClientController::instance()->SessionName().empty())
    return;

  qDebug() << "PerpetualData::onMyFiles()";

  UserSpaceFileSystem::instance()->explore(UserSpaceFileSystem::MY_FILES);
}

void PerpetualData::onPrivateShares() {
  if (ClientController::instance()->SessionName().empty())
    return;

  qDebug() << "PerpetualData::onPrivateShares()";

  UserSpaceFileSystem::instance()->explore(UserSpaceFileSystem::PRIVATE_SHARES);
}

void PerpetualData::onGoOffline(bool b) {
  if (b) {
    SystemTrayIcon::instance()->ChangeStatus(1);
    ClientController::instance()->SetConnectionStatus(1);
  } else {
    SystemTrayIcon::instance()->ChangeStatus(0);
    ClientController::instance()->SetConnectionStatus(0);
  }
}

void PerpetualData::onSaveSession() {
  SaveSessionThread *sst = new SaveSessionThread();
  connect(sst,  SIGNAL(completed(int)),
          this, SLOT(onSaveSessionCompleted(int)));

  sst->start();
}

void PerpetualData::onToggleFullScreen(bool b) {
  if (b) {
    showFullScreen();
  } else {
    showNormal();
  }
}

void PerpetualData::onApplicationActionTriggered() {
  QAction* action = qobject_cast<QAction*>(sender());
  if (!action) {
      return;
  }

  const QString appPath = action->data().toString();
  if (appPath.isEmpty()) {
      qWarning() << "PerpetualData::onApplicationActionTriggered: action"
                 << action->text()
                 << "did not specify app path";
  }

  if (!QProcess::startDetached(appPath)) {
      qWarning() << "PerpetualData::onApplicationActionTriggered: failed to "
                    "start" << appPath << "for action" << action->text();
  }
}

void PerpetualData::onMessageReceived(int type,
                                      const QDateTime&,
                                      const QString& sender,
                                      const QString& detail,
                                      const QString&) {
  boost::progress_timer t;
  if (ClientController::MessageType(type) == ClientController::TEXT) {
    std::list<std::string> theList;
    int result =
        ClientController::instance()->ConversationExits(sender.toStdString());

    if (result != 0) {
      PersonalMessages* mess_ = new PersonalMessages(this, sender);

      // QFile file(":/qss/defaultWithWhite1.qss");
      // file.open(QFile::ReadOnly);
      // QString styleSheet = QLatin1String(file.readAll());

      QPoint loc = this->mapToGlobal(this->pos());
      QRect rec(QApplication::desktop()->availableGeometry(mess_));
      rec.moveTopLeft(QPoint(-420, -255));

      int count = 0;
      while (!rec.contains(loc, true)) {
        if (count < 20) {
        loc.setX(loc.x() - 50);
        if (loc.y() > 100)
          loc.setY(loc.y() - 25);
        } else {
          loc.setX(400);
          loc.setY(400);
          break;
        }
        count++;
      }

      // mess_->setStyleSheet(styleSheet);
      mess_->move(loc);
      mess_->setMessage(tr("%1").arg(detail));
      mess_->show();
    } else {
      foreach(QWidget *widget, QApplication::allWidgets()) {
        PersonalMessages *mess = qobject_cast<PersonalMessages*>(widget);
        if (mess) {
          if (mess->getName() == sender) {
            mess->setMessage(tr("%1").arg(detail));
            mess->show();
          }
        }
      }
    }
  } else if (ClientController::MessageType(type) == ClientController::INVITE) {
    // TODO(Team#5#): 2010-01-13 - handle Invite
  } else if (ClientController::MessageType(type) == ClientController::EMAIL) {
    // TODO(Stephen) HANDLE New email message
  } else {
    printf("Type != ClientController::TEXT && ClientController::INVITE\n");
  }
}

void PerpetualData::onShareReceived(const QString& from,
                                    const QString& share_name) {
  QString title = tr("Share received");
  QString message = tr("'%1' has shared '%2' with you")
                    .arg(from).arg(share_name);

  SystemTrayIcon::instance()->showMessage(title, message);
}

void PerpetualData::onEmailReceived(const QString &subject,
                                    const QString &conversation,
                                    const QString &message,
                                    const QString &sender,
                                    const QString &date) {
  userPanels_->setEmailLabel("New E-mail!");
  SystemTrayIcon::instance()->showMessage("New Email", "You have new email");

  QString emailRootPath = QString::fromStdString(file_system::MaidsafeHomeDir(
                          ClientController::instance()->SessionName()).string())
                              .append("/Emails/");
  try {
    if (!boost::filesystem::exists(emailRootPath.toStdString()))
      boost::filesystem::create_directories(emailRootPath.toStdString());
  }
  catch(const std::exception &e) {
    qDebug() << "PerpetualData::onEmailReceived - Failed to create "
             << emailRootPath;
    return;
  }

  QString emailFolder = "/Emails/";

  std::string tidyRelPathStr =
      ClientController::instance()->TidyPath(emailFolder.toStdString());
  QString emailFolderPath = QString::fromStdString(tidyRelPathStr);

  std::map<std::string, ClientController::ItemType> children;
  ClientController::instance()->readdir(emailFolderPath, &children);

  QString emailFullPath;
  emailFullPath = QString("%1%2_%3.pdmail")
                      .arg(emailRootPath)
                      .arg(subject)
                      .arg(conversation);

  QString emailMaidsafePath;
  emailMaidsafePath = QString("%1%2_%3.pdmail")
                          .arg(emailFolder)
                          .arg(subject)
                          .arg(conversation);

  std::string tidyEmail =
      ClientController::instance()->TidyPath(emailMaidsafePath.toStdString());
  QString tidyEmailMaidsafePath = QString::fromStdString(tidyEmail);

  try {
    std::ofstream myfile;
    myfile.open(emailFullPath.toStdString().c_str(), std::ios::app);
    // SAVE AS XML
    QString htmlMessage = tr("From : %1 at %2 <br /> %3 <br /> %4")
        .prepend("<span style=\"background-color:#CCFF99\"><br />")
        .arg(sender)
        .arg(date)
        .arg(subject)
        .arg(message)
        .append("</span>");
    myfile << htmlMessage.toStdString();
    myfile.close();

    SaveFileThread* sft = new SaveFileThread(tidyEmailMaidsafePath, this);
    connect(sft,  SIGNAL(saveFileCompleted(int, const QString&)),
          this, SLOT(onSaveFileCompleted(int, const QString&)));
    sft->start();
  }
  catch(const std::exception&) {
    qDebug() << "Create File Failed";
  }
}

void PerpetualData::onSaveFileCompleted(int success, const QString& filepath) {
  qDebug() << "onSaveFileCompleted : " << filepath;
  if (success != -1) {
    std::string dir = filepath.toStdString();
    dir.erase(0, 1);
    QString rootPath_ = QString::fromStdString(file_system::MaidsafeHomeDir(
                  ClientController::instance()->SessionName()).string()+"/");

    std::string fullFilePath(rootPath_.toStdString() + filepath.toStdString());

    if (fs::exists(fullFilePath)) {
      try {
        fs::remove(fullFilePath);
        qDebug() << "Remove File Success:"
                 << QString::fromStdString(fullFilePath);
      }
      catch(const std::exception&) {
        qDebug() << "Remove File failure:"
                 << QString::fromStdString(fullFilePath);
      }
    }
  }
}

void PerpetualData::onFileReceived(const QString& sender,
                                   const QString& filename, const QString& tag,
                                   int sizeLow, int sizeHigh,
                                   const ClientController::ItemType& type) {
  QMessageBox msgBox;
  msgBox.setText(tr("%1 is sending you: %2")
                 .arg(sender)
                 .arg(filename));
  msgBox.setStandardButtons(QMessageBox::Save | QMessageBox::Cancel);
  msgBox.setDefaultButton(QMessageBox::Save);
  int ret = msgBox.exec();

  int n;
  QString directory;
  QString root;

  switch (ret) {
    case QMessageBox::Save: {
      // Save
#ifdef PD_LIGHT
      bool ok;
      QString text = QInputDialog::getText(this, tr("Save File As"),
                                        tr("Filename"),
                                        QLineEdit::Normal, "", &ok);
      if (ok && !text.isEmpty()) {
        QString s = QString("My Files\\%1").arg(text);

        n = ClientController::instance()->AddInstantFile(sender, filename, tag,
                                                         sizeLow, sizeHigh,
                                                         type, s);
      }
#else

#ifdef __WIN32__
      root = QString("%1:\\My Files").
             arg(ClientController::instance()->WinDrive());
#else
      root = QString::fromStdString(file_system::MaidsafeFuseDir(
          ClientController::instance()->SessionName()).string() +
          "/My Files");
#endif
      root += "/" + filename;
      qfd_ = new QFileDialog(this, tr("Save File As..."), root);
      connect(qfd_, SIGNAL(directoryEntered(const QString&)),
              this, SLOT(onDirectoryEntered(const QString&)));
      qfd_->setFileMode(QFileDialog::AnyFile);
      qfd_->setAcceptMode(QFileDialog::AcceptSave);

      int result = qfd_->exec();
      if (result == QDialog::Rejected) {
        return;
      }
      QStringList fileNames = qfd_->selectedFiles();
      directory = fileNames.at(0);
#ifdef DEBUG
      printf("PerpetualData::onFileReceived - Dir chosen: %s\n",
             directory.toStdString().c_str());
#endif

#ifdef __WIN32__
      std::string s = directory.toStdString();
      s = s.substr(2, s.length()-1);
#else
      std::string s(file_system::MakeRelativeMSPath(directory.toStdString(),
          ClientController::instance()->SessionName()).string());
#endif

#ifdef DEBUG
      printf("PerpetualData::onFileReceived - Dir chosen: -%s-\n", s.c_str());
#endif
      n = ClientController::instance()->AddInstantFile(
              sender, filename, tag, sizeLow, sizeHigh, type,
              QString::fromStdString(s));

#ifdef DEBUG
      printf("PerpetualData::onFileReceived - Res: %i\n", n);
#endif
#endif  // end of elseif PD_LIGHT
      if (n == 0) {
        QString title = tr("File received");
        QString message = tr("'%1' has shared the file '%2' with you")
                          .arg(sender)
                          .arg(filename);

        SystemTrayIcon::instance()->showMessage(title, message);
      }
      break;
    }
    case QMessageBox::Cancel:
      // Cancel
      break;
    default:
      // Default
      break;
  }
}

void PerpetualData::onUnreadMessagesChanged(int count) {
  qDebug() << "PerpetualData::onUnreadMessagesChanged:" << count;
  QString text;
  if (state_ == LOGGED_IN) {
    text = tr("%n unread message(s)", "", count);
  }
  message_status_->setText(text);
}

void PerpetualData::onConnectionStatusChanged(int status) {
  SystemTrayIcon::instance()->ChangeStatus(status);
  QString title(tr("Connection status"));
  QString message;
  switch (status) {
    case 0: message = tr("You are connected!"); break;
    case 1: message = tr("You are off-line!"); break;
  }
  SystemTrayIcon::instance()->showMessage(title, message);
}

void PerpetualData::onDirectoryEntered(const QString& dir) {
  QString root;

#ifdef __WIN32__
  root = QString(ClientController::instance()->WinDrive());

  if (!dir.startsWith(root, Qt::CaseInsensitive)) {
    root = QString("%1:\\My Files").
         arg(ClientController::instance()->WinDrive());
    qfd_->setDirectory(root);
  }
#else
  root = QString::fromStdString(file_system::MaidsafeFuseDir(
      ClientController::instance()->SessionName()).string());

  if (!dir.startsWith(root, Qt::CaseInsensitive)) {
    root = QString::fromStdString(file_system::MaidsafeFuseDir(
        ClientController::instance()->SessionName()).string() +
        "/My Files");
    qfd_->setDirectory(root);
  }
#endif
}

void PerpetualData::onSettingsTriggered() {
  qDebug() << "in onSettingsTriggered()";
    settings_ = new UserSettings;

    connect(settings_, SIGNAL(langChanged(const QString&)),
          this,                 SLOT(onLangChanged(const QString&)));

    QFile file(":/qss/defaultWithWhite1.qss");
    file.open(QFile::ReadOnly);
    QString styleSheet = QLatin1String(file.readAll());
    settings_->setStyleSheet(styleSheet);
    settings_->exec();
}

void PerpetualData::onOnlineTriggered() {
}

void PerpetualData::onAwayTriggered() {
}

void PerpetualData::onBusyTriggered() {
}

void PerpetualData::onOffline_2Triggered() {
}

void PerpetualData::onBlackThemeTriggered() {
  QFile file(":/qss/black_theme.qss");
  file.open(QFile::ReadOnly);
  QString styleSheet = QLatin1String(file.readAll());

  qApp->setStyleSheet(styleSheet);
}
void PerpetualData::onBlueThemeTriggered() {
  QFile file(":/qss/blue_theme.qss");
  file.open(QFile::ReadOnly);
  QString styleSheet = QLatin1String(file.readAll());

  qApp->setStyleSheet(styleSheet);
}
void PerpetualData::onGreenThemeTriggered() {
  QFile file(":/qss/green_theme.qss");
  file.open(QFile::ReadOnly);
  QString styleSheet = QLatin1String(file.readAll());

  qApp->setStyleSheet(styleSheet);
}
void PerpetualData::onRedThemeTriggered() {
  QFile file(":/qss/red_theme.qss");
  file.open(QFile::ReadOnly);
  QString styleSheet = QLatin1String(file.readAll());

  qApp->setStyleSheet(styleSheet);
}

void PerpetualData::onEmailTriggered() {
  userPanels_->setEmailLabel("");
  inbox_ = new UserInbox(this);
  inbox_->show();
}

void PerpetualData::onLogoutUserCompleted(bool success) {
  onUnmountCompleted(success);
}

void PerpetualData::showLoggedInMenu() {
  actions_[LOGOUT]->setEnabled(true);
  actions_[OFFLINE_2]->setEnabled(true);
}

void PerpetualData::showLoggedOutMenu() {
  actions_[LOGOUT]->setEnabled(false);
  actions_[PRIVATE_SHARES]->setEnabled(false);
  actions_[GO_OFFLINE]->setEnabled(false);
  actions_[SETTINGS]->setEnabled(false);
//  actions_[EMAIL]->setEnabled(false);
  actions_[OFFLINE_2]->setEnabled(false);
}

void PerpetualData::onPublicUsernameChosen() {
  actions_[PRIVATE_SHARES]->setEnabled(true);
  actions_[GO_OFFLINE]->setEnabled(true);
  actions_[SETTINGS]->setEnabled(true);
 // actions_[EMAIL]->setEnabled(true);
}

void PerpetualData::onOffTriggered() {
  userPanels_->setHintLevel(ClientController::OFF);
}
void PerpetualData::onSmallTriggered() {
  userPanels_->setHintLevel(ClientController::SMALL);
}
void PerpetualData::onFullTriggered() {
  userPanels_->setHintLevel(ClientController::FULL);
}

void PerpetualData::onManualTriggered() {
  QDesktopServices::openUrl(QUrl("www.maidsafe.net/help/"));
}

void PerpetualData::onUpdateTriggered() {
  QString program = "./autoupdate";
  QStringList arguments;
  arguments << "--mode" << "unattended";

  QProcess *myProcess = new QProcess(this);
  myProcess->start(program, arguments);

  connect(myProcess, SIGNAL(finished(int, QProcess::ExitStatus)),
          this,      SLOT(onUpdateChecked(int, QProcess::ExitStatus)));
}

void PerpetualData::onUpdateChecked(int code, QProcess::ExitStatus status) {
  if (code == 0) {
    QMessageBox msgBox;
    msgBox.setText(tr("New Update Available"));
    msgBox.setInformativeText(tr("Would you like to install?"));
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::Yes);
    int ret = msgBox.exec();

    if (ret == QMessageBox::Yes) {
      QString program = "./autoupdate";
      QStringList arguments;
      QProcess *myProcess = new QProcess(this);
      myProcess->start(program, arguments);
    }
  } else {
    QMessageBox msgBox;
    msgBox.setText(tr("You are up to date!"));
    msgBox.exec();
  }
}

void PerpetualData::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

void PerpetualData::onLangChanged(const QString &lang) {
  qtTranslator->load("qt_" + lang,
           QLibraryInfo::location(QLibraryInfo::TranslationsPath));
  qApp->installTranslator(qtTranslator);

  bool res = myAppTranslator->load(":/translations/pd_translation_" + lang);
  if (res) {
    qApp->installTranslator(myAppTranslator);
    ui_.retranslateUi(this);
  }
}
