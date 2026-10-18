// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "audio_output.h"

#include "agent_files.h"

#include <QFileSystemWatcher>
#include <QProcess>
#include <QStandardPaths>
#include <QTimer>

AudioOutput::AudioOutput(const QString &run_dir, QObject *parent) : QObject(parent), run_dir_(run_dir) {
	// The directory, not the file, as DisplaySleep watches it.
	watcher_ = new QFileSystemWatcher(QStringList{run_dir_}, this);
	connect(watcher_, &QFileSystemWatcher::directoryChanged, this, &AudioOutput::reload);
	reload();
}

void AudioOutput::reload() {
	QString output = load_audio_output(run_dir_);
	if (output == applied_ || busy_ || missing_) {
		return;
	}
	if (QStandardPaths::findExecutable("wpctl").isEmpty()) {
		missing_ = true;
		qWarning("wisp-greeter: no wpctl, so the audio output is WirePlumber's own choice");
		return;
	}
	busy_ = true;
	auto *wpctl = new QProcess(this);
	wpctl->setProcessChannelMode(QProcess::ForwardedErrorChannel);
	wpctl->setStandardOutputFile(QProcess::nullDevice());
	connect(wpctl, &QProcess::finished, this, [this, wpctl, output](int code, QProcess::ExitStatus status) {
		wpctl->deleteLater();
		busy_ = false;
		if (status == QProcess::NormalExit && code == 0) {
			applied_ = output;
			retry_ms_ = 1000;
			qInfo("wisp-greeter: audio output: %s", qPrintable(output));
			reload(); // the profile may have changed again meanwhile
		} else {
			// PipeWire may not be up yet, this early in the session.
			QTimer::singleShot(retry_ms_, this, &AudioOutput::reload);
			retry_ms_ = qMin(retry_ms_ * 2, 60000);
		}
	});
	wpctl->start("wpctl", {"settings", "--save", "wisp.audio-output", output});
}
