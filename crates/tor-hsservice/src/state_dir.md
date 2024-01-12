# LISTING OF AN ARTI STATE DIRECTORY for planning `state_dir.rs`

TODO HSS delete these random notes at some point
(possibly after making extra docs somewhere about these things?)

```text
keymgr

    keystore/

dirmgr
not in state/ because ???
storage.rs ad hoc sqlite3
EXPIRY built-in

	dir_blobs/
	dir_blobs/con:microdesc:sha3-256-3f4d5d6519d51b20d7161d3f12cb7e23114d0f0f4d252a73077dfe9719011962
	dir.sqlite3

tor_persist
FsStateMgr
.local/share/arti/state.lock

	state/
	state/state.lock

guardmgr
via storage handle
EXPIRTY singleton

	state/guards.json

circmgr?
via storage handle
EXPIRTY singleton

	state/circuit_timeouts.json

ipt_mgr x2
via storage handle
*no* lock against multiple instantiation of same HS
EXPIRTY needs to linked to hs (ie to instance)

	state/hs_iptpub_ztest.json
	state/hs_ipts_ztest.json

?
not per instance ?
should it be ?
no locking ?
	pt_state/

?
  3161169      0 -rw-r--r--   1 rustcargo rustcargo        0 Apr 28  2022 .local/share/arti/state.lock
	state.lock 

HS IPT replay log
ad-hoc via Path
lock against multiple instantiation of same HS
secondary internal lock via mutex
EXPIRY whole dir needs to be linked to hs
EXPIRY needs internal expiry mechanism too

	hss_iptreplay/
	hss_iptreplay/replay_ztest/
	hss_iptreplay/replay_ztest/lock
	hss_iptreplay/replay_ztest/9aa9517e6901c280a550911d3a3c679630403db1c622eedefbdf1715297f795f.bin
	hss_iptreplay/replay_ztest/92d897263497b7e9f998bc7b14cb60a09bfb1beb418cc8266b7e1cc36709b3bf.bin
	hss_iptreplay/replay_ztest/816885a3bf50c90f659304406bde9df0ec926c4b62c556a423b0f6ee7e646c0c.bin
	hss_iptreplay/replay_ztest/62355f8672a24cd76e3f6f769fdb66f829aca898824f88cd16f5dca12cab0fd1.bin
	hss_iptreplay/replay_ztest/7c3bc3ff6f8737b29bc54fd2dd0addf598dad2b69a3993e9f962c512fa42d6f7.bin
	hss_iptreplay/replay_ztest/a35dab4c73c2a2492833c38ea127eb64dfd62b03104b570cd303069e45db9cbb.bin

```
