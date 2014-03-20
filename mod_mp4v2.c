/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2011, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Anthony Minessale II <anthm@freeswitch.org>
 * Seven Du <dujinfang@gmail.com>
 *
 * mod_mp4v2 -- FS Video File Format
 *
 * reference: http://svn.gnumonks.org/trunk/21c3-video/cutting_tagging/tools/mpeg4ip-1.2/doc/about_hint_tracks.txt
 *
 * status: codec is hard codec to PCMU 8000HZ for audio and H264 for video
 *         tested with lib mp4v2-2.0.0
 *         video might not propaly hinted, so no video when playing with play_mp4 in mod_mp4, audio seems fine
 *         hope we could merge with mod_mp4 but I failed to contact the origin author
 */

#include <switch.h>

#include <mp4v2/mp4v2.h>
#include <mp4av_h264.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_mp4v2_load);
SWITCH_MODULE_DEFINITION(mod_mp4v2, mod_mp4v2_load, NULL, NULL);

struct record_helper {
	switch_core_session_t *session;
	switch_mutex_t *mutex;
	MP4FileHandle fd;
	MP4TrackId video_track;
	MP4TrackId audio_track;
	MP4TrackId hint_track;
	int up;
    switch_size_t shared_ts;
};

#define FPS 15 // frame rate
#define DURATION MP4_INVALID_DURATION

static void *SWITCH_THREAD_FUNC record_video_thread(switch_thread_t *thread, void *obj)
{
	struct record_helper *eh = obj;
	switch_core_session_t *session = eh->session;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_status_t status;
	switch_frame_t *read_frame;
	uint bytes;
	MP4FileHandle mp4;
	MP4TrackId video;
	MP4TrackId hint;
	unsigned char buf[20480];
	int len = 0;
	uint8_t iframe = 0;
	uint32_t *size = (uint32_t *)buf;
	uint8_t *hdr = NULL;
	uint8_t fragment_type;
	uint8_t nal_type;
	int sample_id = 1;
	uint8_t start_bit;
	int sps_set = 0;
	int pps_set = 0;
	int hint_set = 0;
	switch_core_session_message_t msg = { 0 };
	int hint_start = 0;
	int offset = 0;

	eh->up = 1;
	mp4 = eh->fd;

	switch_mutex_lock(eh->mutex);

	MP4SetTimeScale(mp4, 90000);
	video = MP4AddH264VideoTrack(mp4, 90000, 90000/FPS, 352, 288, H264_PROFILE_BASELINE, 0xe0, 0x1f, 3);

	if (video == MP4_INVALID_TRACK_ID) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "invalid video track!\n");
		goto end;
	}

	hint = MP4AddHintTrack(mp4, video);

	if (hint == MP4_INVALID_TRACK_ID) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "invalid hint track!\n");
		goto end;
	}

	/*
	MP4SetVideoProfileLevel sets the minumum profile/level of MPEG-4 video support necessary to render the contents of the file.

	ISO/IEC 14496-1:2001 MPEG-4 Systems defines the following values:
	0x00 Reserved
	0x01 Simple Profile @ Level 3
	0x02 Simple Profile @ Level 2
	0x03 Simple Profile @ Level 1
	0x04 Simple Scalable Profile @ Level 2
	0x05 Simple Scalable Profile @ Level 1
	0x06 Core Profile @ Level 2
	0x07 Core Profile @ Level 1
	0x08 Main Profile @ Level 4
	0x09 Main Profile @ Level 3
	0x0A Main Profile @ Level 2
	0x0B N-Bit Profile @ Level 2
	0x0C Hybrid Profile @ Level 2
	0x0D Hybrid Profile @ Level 1
	0x0E Basic Animated Texture @ Level 2
	0x0F Basic Animated Texture @ Level 1
	0x10 Scalable Texture @ Level 3
	0x11 Scalable Texture @ Level 2
	0x12 Scalable Texture @ Level 1
	0x13 Simple Face Animation @ Level 2
	0x14 Simple Face Animation @ Level 1
	0x15-0x7F Reserved
	0x80-0xFD User private
	0xFE No audio profile specified
	0xFF No audio required
	*/
	MP4SetVideoProfileLevel(mp4, 0x7F);

	switch_mutex_unlock(eh->mutex);

	/* Tell the channel to request a fresh vid frame */
	msg.from = __FILE__;
	msg.message_id = SWITCH_MESSAGE_INDICATE_VIDEO_REFRESH_REQ;
	switch_core_session_receive_message(session, &msg);

	len = 0;
	while (switch_channel_ready(channel) && eh->up) {
		status = switch_core_session_read_video_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);

		if (!SWITCH_READ_ACCEPTABLE(status)) {
			break;
		}

		if (switch_test_flag(read_frame, SFF_CNG)) {
			continue;
		}

		bytes = read_frame->datalen;

		if (bytes > 2000) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "xxxxxxxx buffer overflow\n");
			continue;
		}

		hdr = read_frame->data;
		fragment_type = hdr[0] & 0x1f;
		nal_type = hdr[1] & 0x1f;
		start_bit = hdr[1] & 0x80;
		iframe = (((fragment_type == 28 || fragment_type == 29) && nal_type == 5 && start_bit == 128) || fragment_type == 5 || fragment_type ==7 || fragment_type ==8) ? 1 : 0;

#if 0
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%02x %02x %02x | len:%d m:%d st:%d i:%d\n", hdr[0], hdr[1], hdr[2], bytes, read_frame->m, start_bit, iframe);
#endif

		// echo back
		switch_core_session_write_video_frame(session, read_frame, SWITCH_IO_FLAG_NONE, 0);

		if (fragment_type == 7 && !sps_set) { //sps
			switch_mutex_lock(eh->mutex);
			MP4AddH264SequenceParameterSet(mp4, video, read_frame->data, bytes);
			switch_mutex_unlock(eh->mutex);
			sps_set = 1;
		} else if (fragment_type == 8 && !pps_set) { //pps
			switch_mutex_lock(eh->mutex);
			MP4AddH264PictureParameterSet(mp4, video, read_frame->data, bytes);
			switch_mutex_unlock(eh->mutex);
			pps_set = 1;
		}

		if (!hint_set) {
			uint8_t payload_number = MP4_SET_DYNAMIC_PAYLOAD;
			switch_mutex_lock(eh->mutex);
			MP4SetHintTrackRtpPayload(
				mp4,
				hint,
				"H264",
				&payload_number,
				20480, // magic number, maximum payload size
				NULL,
				false,
				false);
			switch_mutex_unlock(eh->mutex);
			hint_set = 1;
		}

		if ((!sps_set) && (!pps_set)) continue;

		if (len == 0) {
			switch_mutex_lock(eh->mutex);
			MP4AddRtpVideoHint(mp4, hint, iframe, (uint8_t)MP4_INVALID_DURATION);
			switch_mutex_unlock(eh->mutex);

			hint_start = 1;
		}

		offset = len;

		switch_mutex_lock(eh->mutex);
		MP4AddRtpPacket(mp4, hint, read_frame->m, (uint8_t)MP4_INVALID_DURATION);
		MP4AddRtpSampleData(mp4, hint, sample_id++, offset, read_frame->datalen+4);
		switch_mutex_unlock(eh->mutex);

		// offset += 4 + read_frame->datalen;
		len += 4 + read_frame->datalen;

		if (len > 20480) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "buffer overflow!!!! %d\n", len);
		}

		*size = htonl(read_frame->datalen);
		memcpy(size + 1, read_frame->data, read_frame->datalen);

		size = (uint32_t *)((uint8_t *)size + 4 + read_frame->datalen);

		if (read_frame->m) {
			switch_mutex_lock(eh->mutex);
			MP4WriteRtpHint(mp4, hint, MP4_INVALID_DURATION, iframe);
			MP4WriteSample(mp4, video, buf, len, DURATION, 0, iframe);
			switch_mutex_unlock(eh->mutex);
			len = 0;
			size = (uint32_t *)buf;

		}

	}

end:
	eh->up = 0;
	return NULL;
}

SWITCH_STANDARD_APP(record_mp4_function)
{
	switch_status_t status;
	switch_frame_t *read_frame;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct record_helper eh = { 0 };
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;
	MP4FileHandle fd;
	MP4TrackId audio;
	MP4TrackId audio_hint;
	switch_mutex_t *mutex = NULL;
	// switch_codec_t codec, *vid_codec;
	switch_codec_implementation_t read_impl = { 0 };
	switch_dtmf_t dtmf = { 0 };
	int count = 0, sanity = 30;
	// int i = 0;
	switch_codec_t codec;
	uint8_t payload = 0;
	int size = 160;
	int duration = size;
	int sample_id = 1;
	switch_event_t *event;

	memset(&codec, 0, sizeof(switch_codec_t));

	switch_core_session_get_read_impl(session, &read_impl);
	switch_channel_answer(channel);

	switch_channel_set_variable(channel, SWITCH_PLAYBACK_TERMINATOR_USED, "");

	while (switch_channel_up(channel) && !switch_channel_test_flag(channel, CF_VIDEO)) {
		switch_yield(10000);

		if (count) count--;

		if (count == 0) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "%s waiting for video.\n", switch_channel_get_name(channel));
			count = 100;
			if (!--sanity) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "%s timeout waiting for video.\n",
								  switch_channel_get_name(channel));
				switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Got timeout while waiting for video");
				return;
			}
		}
	}

	if (!switch_channel_ready(channel)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "%s not ready.\n", switch_channel_get_name(channel));
		switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Channel not ready");
		return;
	}

	if ((fd = MP4CreateEx((char*)data, 0, 1, 1, NULL, 0, NULL, 0)) == MP4_INVALID_FILE_HANDLE) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Error opening file %s\n", (char *) data);
		switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Got error while opening file");
		return;
	}

	audio = MP4AddULawAudioTrack(fd, 8000);
	MP4SetTrackIntegerProperty(fd, audio, "mdia.minf.stbl.stsd.ulaw.channels", 1);
	MP4SetTrackIntegerProperty(fd, audio, "mdia.minf.stbl.stsd.ulaw.sampleSize", 8);

	audio_hint = MP4AddHintTrack(fd, audio);

	MP4SetHintTrackRtpPayload(fd, audio_hint, "PCMU", &payload, 0, NULL, 1, 0);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ms: %d, ts: %d\n", read_impl.microseconds_per_packet, read_impl.samples_per_second /(read_impl.microseconds_per_packet / 1000) / 2);

	/* MP4SetAudioProfileLevel sets the minumum profile/level of MPEG-4 audio support necessary to render the contents of the file.
	ISO/IEC 14496-1:2001 MPEG-4 Systems defines the following values:
	0x00 Reserved
	0x01 Main Profile @ Level 1
	0x02 Main Profile @ Level 2
	0x03 Main Profile @ Level 3
	0x04 Main Profile @ Level 4
	0x05 Scalable Profile @ Level 1
	0x06 Scalable Profile @ Level 2
	0x07 Scalable Profile @ Level 3
	0x08 Scalable Profile @ Level 4
	0x09 Speech Profile @ Level 1
	0x0A Speech Profile @ Level 2
	0x0B Synthesis Profile @ Level 1
	0x0C Synthesis Profile @ Level 2
	0x0D Synthesis Profile @ Level 3
	0x0E-0x7F Reserved
	0x80-0xFD User private
	0xFE No audio profile specified
	0xFF No audio required
	*/
    MP4SetAudioProfileLevel(fd, 0x7F);

    if (read_impl.ianacode != 0) {
		if (switch_core_codec_init(&codec,
								   "PCMU",
								   NULL,
								   read_impl.samples_per_second,
								   read_impl.microseconds_per_packet / 1000,
								   1, SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE,
								   NULL, switch_core_session_get_pool(session)) == SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Audio Codec Activation Success\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Audio Codec Activation Fail\n");
			switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Audio codec activation failed");
			goto end;
		}
		switch_core_session_set_read_codec(session, &codec);
	}

	if (switch_channel_test_flag(channel, CF_VIDEO)) {

		switch_mutex_init(&mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
		eh.mutex = mutex;
		eh.fd = fd;
		eh.session = session;
		switch_threadattr_create(&thd_attr, switch_core_session_get_pool(session));
		switch_threadattr_detach_set(thd_attr, 1);
		switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
		switch_thread_create(&thread, thd_attr, record_video_thread, &eh, switch_core_session_get_pool(session));
	}

	if (switch_event_create(&event, SWITCH_EVENT_RECORD_START) == SWITCH_STATUS_SUCCESS) {
		switch_channel_event_set_data(channel, event);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Record-File-Path", (char *)data);
		switch_event_fire(&event);
	}

	while (switch_channel_ready(channel)) {

		status = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_SINGLE_READ, 0);

		if (switch_channel_test_flag(channel, CF_BREAK)) {
			switch_channel_clear_flag(channel, CF_BREAK);
			eh.up = 0;
			break;
		}

		switch_ivr_parse_all_events(session);

		//check for dtmf interrupts
		if (switch_channel_has_dtmf(channel)) {
			const char * terminators = switch_channel_get_variable(channel, SWITCH_PLAYBACK_TERMINATORS_VARIABLE);
			switch_channel_dequeue_dtmf(channel, &dtmf);

			if (terminators && !strcasecmp(terminators, "none"))
			{
				terminators = NULL;
			}

			if (terminators && strchr(terminators, dtmf.digit)) {

				char sbuf[2] = {dtmf.digit, '\0'};
				switch_channel_set_variable(channel, SWITCH_PLAYBACK_TERMINATOR_USED, sbuf);
				eh.up = 0;
				break;
			}
		}

		if (!SWITCH_READ_ACCEPTABLE(status)) {
			eh.up = 0;
			break;
		}

        switch_core_session_write_frame(session, read_frame, SWITCH_IO_FLAG_NONE, 0);

		if (switch_test_flag(read_frame, SFF_CNG)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cng, datalen:%d\n", read_frame->datalen);
			// continue;
			memset(read_frame->data, 0x0, 160);
		}

		if (read_frame->datalen != 160 ) continue;

		if (mutex) switch_mutex_lock(mutex);

		duration = duration;

		MP4WriteSample(fd, audio, read_frame->data, size, duration, 0, 1);
		MP4AddRtpHint(fd, audio_hint);
		MP4AddRtpPacket(fd, audio_hint, 1, 0);
		MP4AddRtpSampleData(fd, audio_hint, sample_id, 0, size);
		MP4WriteRtpHint(fd, audio_hint, duration, 1);

		sample_id++;

		if (mutex) switch_mutex_unlock(mutex);
	}

	switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "OK");

	if (switch_event_create(&event, SWITCH_EVENT_RECORD_STOP) == SWITCH_STATUS_SUCCESS) {
		switch_channel_event_set_data(channel, event);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Record-File-Path", (char *)data);
		switch_event_fire(&event);
	}

end:

	if (eh.up) {
		while (eh.up) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "waiting video thread to be done ...\n");
			switch_cond_next();
		}
	}

	switch_core_session_set_read_codec(session, NULL);

	if (eh.fd != MP4_INVALID_FILE_HANDLE) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "closing file %s\n", (char *)data);
		MP4Close(eh.fd, 0);
	}

	if (switch_core_codec_ready(&codec)) switch_core_codec_destroy(&codec);

}

// SWITCH_STANDARD_APP(play_mp4_function)
// {

// }


struct mp4_file_context {
	MP4FileHandle fd;
	MP4TrackId audio;
	MP4TrackId video;
	MP4TrackId audio_hint;
	MP4TrackId video_hint;
	int audio_sample_id;
	int video_sample_id;
	switch_codec_t raw_codec;
	switch_codec_t audio_codec;
	switch_mutex_t *mutex;
	switch_buffer_t *buf;
	int sps_set;
	int pps_set;
	int hint_set;
};

typedef struct mp4_file_context mp4_file_context_t;

static switch_status_t mp4_file_open(switch_file_handle_t *handle, const char *path)
{
	mp4_file_context_t *context;
	char *ext;
	unsigned int flags = 0;
	uint8_t payload = 0;

	if ((ext = strrchr(path, '.')) == 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid Format\n");
		return SWITCH_STATUS_GENERR;
	}
	ext++;

	if ((context = switch_core_alloc(handle->memory_pool, sizeof(mp4_file_context_t))) == 0) {
		return SWITCH_STATUS_MEMERR;
	}

	memset(context, 0, sizeof(mp4_file_context_t));

	switch_mutex_init(&context->mutex, SWITCH_MUTEX_NESTED, handle->memory_pool);

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_WRITE)) {
		flags |= SWITCH_FOPEN_WRITE | SWITCH_FOPEN_CREATE;
		if (switch_test_flag(handle, SWITCH_FILE_WRITE_APPEND) || switch_test_flag(handle, SWITCH_FILE_WRITE_OVER)) {
			flags |= SWITCH_FOPEN_READ;
		} else {
			flags |= SWITCH_FOPEN_TRUNCATE;
		}
	}

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_READ)) {
		flags |= SWITCH_FOPEN_READ;
	}

//write only
	if ((context->fd = MP4CreateEx(path, 0, 1, 1, NULL, 0, NULL, 0)) == MP4_INVALID_FILE_HANDLE) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error opening file %s\n", path);
		return SWITCH_STATUS_GENERR;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "sample rate: %d\n", handle->samplerate);

	handle->samplerate = 8000;

	context->audio = MP4AddULawAudioTrack(context->fd, handle->samplerate);
	// context->audio = MP4AddAudioTrack(context->fd, handle->samplerate, MP4_INVALID_DURATION, MP4_PCM16_LITTLE_ENDIAN_AUDIO_TYPE);
	MP4SetAudioProfileLevel(context->fd, 0x7F);

	MP4SetTrackIntegerProperty(context->fd, context->audio, "mdia.minf.stbl.stsd.ulaw.channels", 1);
	MP4SetTrackIntegerProperty(context->fd, context->audio, "mdia.minf.stbl.stsd.ulaw.sampleSize", 8);

	context->audio_hint = MP4AddHintTrack(context->fd, context->audio);
	context->audio_sample_id = 1;
	context->video_sample_id = 1;

	MP4SetHintTrackRtpPayload(context->fd, context->audio_hint, "PCMU", &payload, 0, NULL, 1, 0);

	if (switch_test_flag(handle, SWITCH_FILE_WRITE_APPEND)) {
		int64_t samples = 0;
		switch_file_seek(context->fd, SEEK_END, &samples);
		handle->pos = samples;
	}

	handle->samples = 0;
	// handle->samplerate = 8000;
	// handle->channels = 1;
	handle->format = 0;
	handle->sections = 0;
	handle->seekable = 0;
	handle->speed = 0;
	handle->pos = 0;
	handle->private_info = context;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Opening File [%s] %dhz\n", path, handle->samplerate);

	if (switch_core_codec_init(&context->raw_codec,
							   "L16",
							   NULL,
							   handle->samplerate,
							   20,//ms
							   1, SWITCH_CODEC_FLAG_ENCODE,
							   NULL, handle->memory_pool) == SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Audio Codec Activation Success\n");
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Audio Codec Activation Fail\n");
		goto end;
	}

	if (switch_core_codec_init(&context->audio_codec,
							   "PCMU",
							   NULL,
							   handle->samplerate,
							   20,//ms
							   1, SWITCH_CODEC_FLAG_ENCODE,
							   NULL, handle->memory_pool) == SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Audio Codec Activation Success\n");
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Audio Codec Activation Fail\n");
		goto end;
	}

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_WRITE)) {

	    MP4SetAudioProfileLevel(context->fd, 0x7F);
	}

	switch_buffer_create_dynamic(&context->buf, 512, 512, 1024000);

	return SWITCH_STATUS_SUCCESS;

end:
	if (context->fd) {
		MP4Close(context->fd, 0);
		context->fd = NULL;
	}
	return SWITCH_STATUS_FALSE;
}

static switch_status_t mp4_file_truncate(switch_file_handle_t *handle, int64_t offset)
{
	mp4_file_context_t *context = handle->private_info;
	switch_status_t status;

	if ((status = switch_file_trunc(context->fd, offset)) == SWITCH_STATUS_SUCCESS) {
		handle->pos = 0;
	}

	return status;

}

static switch_status_t mp4_file_close(switch_file_handle_t *handle)
{
	mp4_file_context_t *context = handle->private_info;

	if (context->fd) {
		MP4Close(context->fd, 0);
		context->fd = NULL;
	}

	if (switch_core_codec_ready(&context->raw_codec)) switch_core_codec_destroy(&context->raw_codec);
	if (switch_core_codec_ready(&context->audio_codec)) switch_core_codec_destroy(&context->audio_codec);

	switch_buffer_destroy(&context->buf);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mp4_file_seek(switch_file_handle_t *handle, unsigned int *cur_sample, int64_t samples, int whence)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "seek not implemented\n");
	return SWITCH_STATUS_FALSE;
}

static switch_status_t mp4_file_read(switch_file_handle_t *handle, void *data, size_t *len)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "read not implemented\n");
	return SWITCH_STATUS_FALSE;
}

static switch_status_t mp4_file_write(switch_file_handle_t *handle, void *data, size_t *len)
{
	uint32_t datalen = *len * 2;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	int duration = datalen;
	uint8_t buf[SWITCH_RECOMMENDED_BUFFER_SIZE];
	uint32_t encoded_rate;
	mp4_file_context_t *context = handle->private_info;
	uint32_t size;
	int16_t *xdata = data;

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "writing: %ld\n", (long)(*len));

	if (*len != 160 ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "size %d not supported\n", (int)(*len));
		return SWITCH_STATUS_FALSE;
	}

	if (handle->channels > 1) {
		int i, j;
		int32_t mixed = 0;
		for (i=0; i<*len; i++) {
			for (j = 0; j < handle->channels; j++) {
				mixed += xdata[i * handle->channels + j];
			}
			switch_normalize_to_16bit(mixed);
			xdata[i] = (uint16_t)mixed;
		}
	}

	switch_core_codec_encode(&context->audio_codec,
		&context->raw_codec,
		data,
		datalen,
		handle->samplerate,
		buf, &size, &encoded_rate, 0);

	duration = 160;

	switch_mutex_lock(context->mutex);

	MP4WriteSample(context->fd, context->audio, buf, size, duration, 0, 1);
	MP4AddRtpHint(context->fd, context->audio_hint);
	MP4AddRtpPacket(context->fd, context->audio_hint, 1, 0);
	MP4AddRtpSampleData(context->fd, context->audio_hint, context->audio_sample_id++, 0, size);
	MP4WriteRtpHint(context->fd, context->audio_hint, duration, 1);

	switch_mutex_unlock(context->mutex);

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "audio written: %d\n", size);

	*len = size;
	return status;
}

static switch_status_t mp4_file_write_video(switch_file_handle_t *handle, void *data, size_t *len)
{
	uint32_t datalen = *len - 12;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	int iframe = 0;
	uint32_t size;
	uint8_t *hdr = NULL;
	uint8_t fragment_type;
	uint8_t nal_type;
	uint8_t start_bit;
	switch_rtp_hdr_t *rtp_hdr = data;
	mp4_file_context_t *context = handle->private_info;
	uint8_t payload_number = 0;

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "writing: %ld\n", (long)(*len));

	switch_mutex_lock(context->mutex);
	if (!context->video) {
		// uint8_t payload_number = MP4_SET_DYNAMIC_PAYLOAD;

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Add video track\n");
		context->video = MP4AddH264VideoTrack(context->fd, 90000, 90000/FPS, 352, 288, H264_PROFILE_BASELINE, 0xe0, 0x1f, 3);
		if (context->video == MP4_INVALID_TRACK_ID) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "invalid video track\n");
			switch_mutex_unlock(context->mutex);
			return SWITCH_STATUS_FALSE;
		}

		MP4SetVideoProfileLevel(context->fd, 0x7F);

		context->video_hint = MP4AddHintTrack(context->fd, context->video);

		if (context->video_hint == MP4_INVALID_TRACK_ID) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "invalid hint track!\n");
			switch_mutex_unlock(context->mutex);
			return SWITCH_STATUS_FALSE;
		}

		MP4SetHintTrackRtpPayload(
			context->fd,
			context->video_hint,
			"H264",
			&payload_number,
			20480, // magic number, maximum payload size, can be 0? FIXME
			NULL,
			false,
			false);

		context->video_sample_id = 1;
	}

	switch_mutex_unlock(context->mutex);

	hdr = ((uint8_t *)data + 12);
	fragment_type = hdr[0] & 0x1f;
	nal_type = hdr[1] & 0x1f;
	start_bit = hdr[1] & 0x80;
	iframe = (((fragment_type == 28 || fragment_type == 29) && nal_type == 5 && start_bit == 128) || fragment_type == 5 || fragment_type ==7 || fragment_type ==8) ? 1 : 0;

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%02x %02x %02x | len:%d m:%d st:%d i:%d\n", hdr[0], hdr[1], hdr[2], datalen, rtp_hdr->m, start_bit, iframe);

	if (switch_buffer_inuse(context->buf) == 0) {
		MP4AddRtpVideoHint(context->fd, context->video_hint, iframe, (uint8_t)MP4_INVALID_DURATION);
	}

	MP4AddRtpPacket(context->fd, context->video_hint, rtp_hdr->m, (uint8_t)MP4_INVALID_DURATION);
	MP4AddRtpSampleData(context->fd, context->video_hint, context->video_sample_id++, switch_buffer_inuse(context->buf), datalen + 4);

	size = htonl(datalen);
	switch_buffer_write(context->buf, &size, 4);
	switch_buffer_write(context->buf, hdr, datalen);
	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "---------------------------------- buffering %d bytes\n", datalen);

	switch_mutex_lock(context->mutex);

	if (fragment_type == 7 && !context->sps_set) { //sps
		MP4AddH264SequenceParameterSet(context->fd, context->video, hdr, datalen);
		context->sps_set = 1;
	} else if (fragment_type == 8 && !context->pps_set) { //pps
		MP4AddH264PictureParameterSet(context->fd, context->video, hdr, datalen);
		context->pps_set = 1;
	}

	if (nal_type == 7 || nal_type == 8 || rtp_hdr->m == 0) {
	} else {
		uint32_t used = switch_buffer_inuse(context->buf);
		const void *data;
		switch_buffer_peek_zerocopy(context->buf, &data);
		MP4WriteRtpHint(context->fd, context->video_hint, MP4_INVALID_DURATION, iframe);
		MP4WriteSample(context->fd, context->video, data, used, DURATION, 0, iframe);
		switch_buffer_zero(context->buf);
		// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "----------------------------------- written: %d\n", used);
	}

	switch_mutex_unlock(context->mutex);

	*len = datalen; // FIXME

	status = SWITCH_STATUS_SUCCESS;

	return status;
}

static switch_status_t mp4_file_set_string(switch_file_handle_t *handle, switch_audio_col_t col, const char *string)
{
	return SWITCH_STATUS_FALSE;
}

static switch_status_t mp4_file_get_string(switch_file_handle_t *handle, switch_audio_col_t col, const char **string)
{
	return SWITCH_STATUS_FALSE;
}

static char *supported_formats[2] = { 0 };

SWITCH_MODULE_LOAD_FUNCTION(mod_mp4v2_load)
{
	switch_application_interface_t *app_interface;
	switch_file_interface_t *file_interface;

	supported_formats[0] = "mp4";

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->interface_name = modname;
	file_interface->extens = supported_formats;
	file_interface->file_open = mp4_file_open;
	file_interface->file_close = mp4_file_close;
	file_interface->file_truncate = mp4_file_truncate;
	file_interface->file_read = mp4_file_read;
	file_interface->file_write = mp4_file_write;
	file_interface->file_write_video = mp4_file_write_video;
	file_interface->file_seek = mp4_file_seek;
	file_interface->file_set_string = mp4_file_set_string;
	file_interface->file_get_string = mp4_file_get_string;

	// SWITCH_ADD_APP(app_interface, "play_mp4", "play an mp4 file", "play an mp4 file", play_mp4_function, "<file>", SAF_NONE);
	SWITCH_ADD_APP(app_interface, "record_mp4", "record an mp4 file", "record an mp4 file", record_mp4_function, "<file>", SAF_NONE);

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
