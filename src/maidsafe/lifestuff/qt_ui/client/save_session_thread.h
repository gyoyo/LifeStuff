
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
 *  Created on: May 5, 2009
 *      Author: Team
 */

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_SAVE_SESSION_THREAD_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_SAVE_SESSION_THREAD_H_

#include "maidsafe/lifestuff/qt_ui/client/worker_thread.h"

namespace maidsafe {

namespace lifestuff {

namespace qt_ui {

// Worker thread for adding users
/*!
    Adding a user is blocking and can take a while so we use a worker
    thread to ensure that it doesn't block the main gui.

    Currently intended for single use.
*/
class SaveSessionThread : public WorkerThread {
  Q_OBJECT
 public:
  explicit SaveSessionThread(QObject* parent = 0);
  virtual ~SaveSessionThread();

  virtual void run();

 private:

 signals:
    void completed(int);  //  NOLINT
};

}  // namespace qt_ui

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_SAVE_SESSION_THREAD_H_

