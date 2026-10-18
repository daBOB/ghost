// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Plays sound to the output the profile's audio_output names: "display"
// (HDMI/DisplayPort, kept while the display sleeps), "builtin" (the
// speaker or audio jack) or "auto" (WirePlumber's own choice). The image's
// WirePlumber hook (wireplumber/scripts/wisp/audio-output.lua) does the
// choosing; this sets its wisp.audio-output setting with wpctl, saved so a
// WirePlumber restart keeps it. A new value from Veil applies at once, to a
// running session too: profile.json is watched.
#pragma once

#include <QObject>
#include <QString>

class QFileSystemWatcher;

class AudioOutput : public QObject {
	Q_OBJECT

public:
	AudioOutput(const QString &run_dir, QObject *parent = nullptr);

private:
	void reload();

	QString run_dir_;
	QFileSystemWatcher *watcher_ = nullptr;
	QString applied_; // what wpctl last set; empty: nothing yet
	bool busy_ = false; // a wpctl is running
	int retry_ms_ = 1000; // after a failed wpctl, doubling to a minute
	bool missing_ = false; // wpctl isn't installed (a desktop test run)
};
