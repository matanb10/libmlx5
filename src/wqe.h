/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef WQE_H
#define WQE_H

enum {
	MLX5_WQE_CTRL_CQ_UPDATE	= 2 << 2,
	MLX5_WQE_CTRL_SOLICITED	= 1 << 1,
	MLX5_WQE_CTRL_FENCE	= 4 << 5,
};

enum {
	MLX5_INVALID_LKEY	= 0x100,
};

enum {
	MLX5_EXTENED_UD_AV	= 0x80000000,
};

struct mlx5_wqe_srq_next_seg {
	uint8_t			rsvd0[2];
	uint16_t		next_wqe_index;
	uint8_t			signature;
	uint8_t			rsvd1[11];
};

struct mlx5_wqe_data_seg {
	uint32_t		byte_count;
	uint32_t		lkey;
	uint64_t		addr;
};

struct mlx5_eqe_comp {
	uint32_t	reserved[6];
	uint32_t	cqn;
};

struct mlx5_eqe_qp_srq {
	uint32_t	reserved[6];
	uint32_t	qp_srq_n;
};


struct mlx5_wqe_fmr_seg {
	uint32_t	flags;
	uint32_t	mem_key;
	uint64_t	buf_list;
	uint64_t	start_addr;
	uint64_t	reg_len;
	uint32_t	offset;
	uint32_t	page_size;
	uint32_t	reserved[2];
};

struct mlx4_wqe_fmr_seg {
	uint32_t	flags;
	uint32_t	mem_key;
	uint64_t	buf_list;
	uint64_t	start_addr;
	uint64_t	reg_len;
	uint32_t	offset;
	uint32_t	page_size;
	uint32_t	reserved[2];
};

struct mlx5_wqe_ctrl_seg {
	uint32_t	opmod_idx_opcode;
	uint32_t	qpn_ds;
	uint8_t		signature;
	uint8_t		rsvd[2];
	uint8_t		fm_ce_se;
	uint32_t	imm;
};

struct mlx5_wqe_xrc_seg {
	uint32_t	xrc_srqn;
	uint8_t		rsvd[12];
};

struct mlx5_wqe_masked_atomic_seg {
	uint64_t	swap_add;
	uint64_t	compare;
	uint64_t	swap_add_mask;
	uint64_t	compare_mask;
};

struct mlx5_wqe_av {
	union {
		struct {
			uint32_t	qkey;
			uint32_t	reserved;
		} qkey;
		uint64_t	dc_key;
	} key;
	uint32_t	dqp_dct;
	uint8_t		stat_rate_sl;
	uint8_t		fl_mlid;
	uint16_t	rlid;
	uint8_t		reserved0[10];
	uint8_t		tclass;
	uint8_t		hop_limit;
	uint32_t	grh_gid_fl;
	uint8_t		rgid[16];
};

struct mlx5_wqe_datagram_seg {
	struct mlx5_wqe_av	av;
};

struct mlx5_wqe_raddr_seg {
	uint64_t	raddr;
	uint32_t	rkey;
	uint32_t	reserved;
};

struct mlx5_wqe_atomic_seg {
	uint64_t	swap_add;
	uint64_t	compare;
};

struct mlx5_wqe_inl_data_seg {
	uint32_t	byte_count;
};

struct mlx5_wqe_umr_ctrl_seg {
	uint8_t		flags;
	uint8_t		rsvd0[3];
	uint16_t	klm_octowords;
	uint16_t	bsf_octowords;
	uint64_t	mkey_mask;
	uint8_t		rsvd1[32];
};

struct mlx5_seg_set_psv {
	uint8_t		rsvd[4];
	uint16_t	syndrome;
	uint16_t	status;
	uint16_t	block_guard;
	uint16_t	app_tag;
	uint32_t	ref_tag;
	uint32_t	mkey;
	uint64_t	va;
};

struct mlx5_seg_get_psv {
	uint8_t		rsvd[19];
	uint8_t		num_psv;
	uint32_t	l_key;
	uint64_t	va;
	uint32_t	psv_index[4];
};

struct mlx5_seg_check_psv {
	uint8_t		rsvd0[2];
	uint16_t	err_coalescing_op;
	uint8_t		rsvd1[2];
	uint16_t	xport_err_op;
	uint8_t		rsvd2[2];
	uint16_t	xport_err_mask;
	uint8_t		rsvd3[7];
	uint8_t		num_psv;
	uint32_t	l_key;
	uint64_t	va;
	uint32_t	psv_index[4];
};

struct mlx5_rwqe_sig {
	uint8_t		rsvd0[4];
	uint8_t		signature;
	uint8_t		rsvd1[11];
};

struct mlx5_wqe_signature_seg {
	uint8_t		rsvd0[4];
	uint8_t		signature;
	uint8_t		rsvd1[11];
};

struct mlx5_wqe_inline_seg {
	uint32_t	byte_count;
};


#endif /* WQE_H */
