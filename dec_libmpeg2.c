#include <gpac/filters.h>


#include "config.h"
#include "mpeg2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>


typedef struct
{
	u32 width, height, out_size;
	Bool do_flush;
	GF_FilterPid *ipid, *opid;
	mpeg2dec_t *decoder;
} GF_BaseFilter;

static void libmpeg2dec_finalize(GF_Filter *filter)
{
	GF_BaseFilter *ctx = (GF_BaseFilter *) gf_filter_get_udta(filter);
	if (ctx->decoder) mpeg2_close(ctx->decoder);
}

static GF_Err libmpeg2dec_process(GF_Filter *filter)
{
	u8 *data_dst;
	u8 *data_src;
	u32 size;
	u8 *buffer;

	GF_FilterPacket *pck_dst;
	GF_BaseFilter *ctx = (GF_BaseFilter *) gf_filter_get_udta(filter);

	GF_FilterPacket *pck = gf_filter_pid_get_packet(ctx->ipid);
	if (!pck)
    {
        if (gf_filter_pid_is_eos(ctx->ipid))
        {
            gf_filter_pid_set_eos(ctx->opid);
            return GF_EOS;
        }
        return GF_OK;
    }

	data_src = gf_filter_pck_get_data(pck, &size);
	if (!data_src)
    {
        gf_filter_pid_drop_packet(ctx->ipid);
        return GF_IO_ERR;
    }
	
	mpeg2_buffer(ctx->decoder, data_src, data_src + size);
	const mpeg2_info_t *info = mpeg2_info(ctx->decoder);
	
	while (1) {

		int state = mpeg2_parse(ctx->decoder);
	    
		if (state == STATE_BUFFER) break;
		if (state == STATE_PICTURE) {
			pck_dst = gf_filter_pck_new_alloc(ctx->opid, ctx->out_size, &buffer);
			if (!pck_dst) return GF_OUT_OF_MEM;
			gf_filter_pck_merge_properties(pck, pck_dst);
			memcpy(buffer, info->current_picture->display_offset, ctx->out_size);
			//mpeg2_set_buf(pck_dst, buffer, &ctx->out_size);
			gf_filter_pck_send(pck_dst);
			/*
			GF_FilterPacket *out_pkt = gf_filter_pkt_new(filter);
			gf_filter_pkt_set_data(out_pkt, info->current_picture->fbuf[0],
								   info->sequence->width * info->sequence->height * 3 / 2);
			gf_filter_pkt_set_pts(out_pkt, gf_filter_pkt_get_pts(pkt));
			gf_filter_output(filter, 0, out_pkt);*/
		}
		if (state == STATE_SEQUENCE) {
			ctx-> width = info->sequence->picture_width;
			ctx-> height = info->sequence->picture_height;
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(ctx-> width) );
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(ctx-> height) );
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STRIDE, &PROP_UINT(ctx-> width) );
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(GF_PIXEL_YUV) );
			ctx->out_size = ctx-> width * ctx-> height  * 3 / 2;
		}
	}

	gf_filter_pid_drop_packet(ctx->ipid);

	return GF_OK;

}

static GF_Err libmpeg2dec_config_input(GF_Filter *filter, GF_FilterPid *pid, Bool is_remove)
{
	const GF_PropertyValue *p;
	GF_Err e;
	Bool is_first = GF_FALSE;
	GF_BaseFilter *ctx = gf_filter_get_udta(filter);

	if (is_remove) {
		if (ctx->opid) {
			gf_filter_pid_remove(ctx->opid);
			ctx->opid = NULL;
		}
		ctx->ipid = NULL;
		return GF_OK;
	}
	if (! gf_filter_pid_check_caps(pid)) {
		ctx->do_flush = GF_TRUE;
		return GF_NOT_SUPPORTED;
	}
	ctx->do_flush = GF_FALSE;

	ctx->ipid = pid;
	if (!ctx->opid) {
		ctx->opid = gf_filter_pid_new(filter);
		gf_filter_pid_set_framing_mode(ctx->ipid, GF_TRUE);
		is_first = GF_TRUE;
	}
	//copy properties at init or reconfig
	gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
	gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CODECID, &PROP_UINT(GF_CODECID_RAW) );

	p = gf_filter_pid_get_property(pid, GF_PROP_PID_DECODER_CONFIG);

	return GF_OK;
}

static GF_Err libmpeg2dec_update_arg(GF_Filter *filter, const char *arg_name, const GF_PropertyValue *arg_val)
{
	return GF_OK;
}

GF_Err libmpeg2dec_initialize(GF_Filter *filter)
{
	GF_BaseFilter *stack = gf_filter_get_udta(filter);
	
	//if you filter is a source, this is the right place to start declaring output PIDs, such as above
	stack->decoder = mpeg2_init();

	return GF_OK;
}

static const GF_FilterCapability LIBMPEG2FullCaps[] =
{
	CAP_UINT(GF_CAPS_INPUT,GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
	CAP_UINT(GF_CAPS_INPUT,GF_PROP_PID_CODECID, GF_CODECID_MPEG1),
	CAP_BOOL(GF_CAPS_INPUT_EXCLUDED, GF_PROP_PID_UNFRAMED, GF_TRUE),
	CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
	CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_CODECID, GF_CODECID_RAW),
};

const GF_FilterRegister LIBMPEG2Register = {
	.name = "libmpeg2dec",
	GF_FS_SET_DESCRIPTION("MPEG-1 and MPEG-2 video decoders")
	GF_FS_SET_HELP("This filter decodes MPEG-1 and MPEG-2 video streams using libmpeg2.")
	.private_size = sizeof(GF_BaseFilter),
	.args = NULL,
	.initialize = libmpeg2dec_initialize,
	.finalize = libmpeg2dec_finalize,
	SETCAPS(LIBMPEG2FullCaps),
	.process = libmpeg2dec_process,
	.configure_pid = libmpeg2dec_config_input
};

const GF_FilterRegister * EMSCRIPTEN_KEEPALIVE dynCall_libmpeg2_register(GF_FilterSession *session)
{
	return &LIBMPEG2Register;
}



