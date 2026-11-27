'use strict';
'require view';
'require rpc';
'require ui';
'require dom';
'require poll';

var callStatus = rpc.declare({
	object: 'f50pro-repeater',
	method: 'status'
});

var callScan = rpc.declare({
	object: 'f50pro-repeater',
	method: 'scan'
});

var callConnect = rpc.declare({
	object: 'f50pro-repeater',
	method: 'connect',
	params: ['ssid', 'key', 'encryption', 'band', 'channel']
});

var callDisconnect = rpc.declare({
	object: 'f50pro-repeater',
	method: 'disconnect',
	params: ['ap_band']
});

var callRouteMode = rpc.declare({
	object: 'f50pro-repeater',
	method: 'route_mode',
	params: ['mode']
});

var callApConfig = rpc.declare({
	object: 'f50pro-repeater',
	method: 'ap_config',
	params: ['ssid', 'key', 'encryption']
});

var callRetry = rpc.declare({
	object: 'f50pro-repeater',
	method: 'retry'
});

var CSS = [
	'.f50r-wrap { max-width: 960px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }',
	'.f50r-card { background: var(--surface, var(--background-alt, #fff)); border: 1px solid var(--hairline, var(--border, #e5e7eb)); border-radius: 16px; padding: 16px; }',
	'.f50r-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 12px; }',
	'.f50r-title { margin: 0; font-size: 16px; font-weight: 600; }',
	'.f50r-sub { font-size: 13px; color: var(--text-muted, #6b7280); margin: 4px 0 0; }',
	'.f50r-badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; }',
	'.f50r-badge.ok { background: color-mix(in srgb, var(--success, #16a34a) 16%, transparent); color: var(--success, #15803d); }',
	'.f50r-badge.warn { background: color-mix(in srgb, var(--warning, #d97706) 16%, transparent); color: var(--warning, #b45309); }',
	'.f50r-badge.off { background: color-mix(in srgb, var(--text-muted, #6b7280) 14%, transparent); color: var(--text-muted, #4b5563); }',
	'.f50r-grid3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }',
	'.f50r-stat { background: var(--background-color-low, rgba(127,127,127,0.06)); border: 1px solid var(--hairline, var(--border, #e5e7eb)); border-radius: 12px; padding: 12px; }',
	'.f50r-stat-k { font-size: 12px; color: var(--text-muted, #6b7280); margin-bottom: 4px; }',
	'.f50r-stat-v { font-size: 15px; font-weight: 600; word-break: break-all; }',
	'.f50r-stat-m { font-size: 12px; color: var(--text-muted, #6b7280); margin-top: 4px; line-height: 1.45; white-space: pre-line; }',
	'.f50r-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }',
	'.f50r-btn { min-height: 38px; padding: 8px 14px; border-radius: 10px; border: 1px solid var(--hairline, var(--border, #d1d5db)); background: var(--surface, transparent); color: inherit; font-size: 13px; font-weight: 500; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 6px; }',
	'.f50r-btn.primary { background: var(--brand, var(--primary, #2563eb)); border-color: var(--brand, var(--primary, #2563eb)); color: #fff; }',
	'.f50r-btn.danger { color: var(--danger, #dc2626); border-color: color-mix(in srgb, var(--danger, #dc2626) 45%, transparent); }',
	'.f50r-btn.active { background: color-mix(in srgb, var(--brand, var(--primary, #2563eb)) 14%, transparent); border-color: var(--brand, var(--primary, #2563eb)); color: var(--brand, var(--primary, #2563eb)); font-weight: 600; }',
	'.f50r-btn:disabled { opacity: 0.55; cursor: not-allowed; }',
	'.f50r-seg { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }',
	'.f50r-seg .f50r-btn { flex-direction: column; padding: 10px 8px; text-align: center; line-height: 1.35; }',
	'.f50r-seg-sub { font-size: 11px; font-weight: 400; opacity: 0.8; }',
	'.f50r-filters { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }',
	'.f50r-scan-list { display: flex; flex-direction: column; gap: 8px; max-height: 320px; overflow-y: auto; margin: 12px 0; }',
	'.f50r-scan-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 12px; border: 1px solid var(--hairline, var(--border, #e5e7eb)); border-radius: 12px; cursor: pointer; }',
	'.f50r-scan-row:hover, .f50r-scan-row.selected { border-color: var(--brand, var(--primary, #2563eb)); background: color-mix(in srgb, var(--brand, var(--primary, #2563eb)) 8%, transparent); }',
	'.f50r-scan-main { min-width: 0; flex: 1; }',
	'.f50r-scan-ssid { font-size: 14px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }',
	'.f50r-scan-meta { font-size: 12px; color: var(--text-muted, #6b7280); margin-top: 2px; display: flex; flex-wrap: wrap; gap: 8px; }',
	'.f50r-tag { display: inline-block; padding: 1px 6px; border-radius: 6px; font-size: 11px; font-weight: 600; background: color-mix(in srgb, var(--brand, var(--primary, #2563eb)) 12%, transparent); color: var(--brand, var(--primary, #2563eb)); }',
	'.f50r-tag.b5 { background: color-mix(in srgb, var(--success, #16a34a) 14%, transparent); color: var(--success, #15803d); }',
	'.f50r-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 12px; }',
	'.f50r-field { display: flex; flex-direction: column; gap: 6px; }',
	'.f50r-field.full { grid-column: 1 / -1; }',
	'.f50r-label { font-size: 12px; font-weight: 500; color: var(--text-muted, #6b7280); }',
	'.f50r-input, .f50r-select { width: 100%; box-sizing: border-box; min-height: 38px; padding: 7px 10px; border-radius: 10px; border: 1px solid var(--hairline, var(--border, #d1d5db)); background: var(--surface, transparent); color: inherit; font-size: 14px; }',
	'.f50r-pw-row { display: flex; gap: 8px; }',
	'.f50r-pw-row .f50r-input { flex: 1; min-width: 0; }',
	'.f50r-banner { padding: 10px 12px; border-radius: 10px; font-size: 13px; line-height: 1.5; background: color-mix(in srgb, var(--warning, #d97706) 12%, transparent); border: 1px solid color-mix(in srgb, var(--warning, #d97706) 35%, transparent); margin-top: 10px; }',
	'.f50r-note { font-size: 12px; color: var(--text-muted, #6b7280); margin-top: 8px; line-height: 1.5; }',
	'@media (max-width: 680px) { .f50r-grid3, .f50r-seg, .f50r-form { grid-template-columns: 1fr; } .f50r-card { padding: 14px; } }'
].join('\n');

function injectCss() {
	if (document.getElementById('f50r-style')) return;
	var st = document.createElement('style');
	st.id = 'f50r-style';
	st.textContent = CSS;
	document.head.appendChild(st);
}

function signalDesc(dbm) {
	if (dbm == null) return '--';
	if (dbm >= -55) return dbm + ' dBm (极强)';
	if (dbm >= -68) return dbm + ' dBm (良好)';
	if (dbm >= -78) return dbm + ' dBm (一般)';
	return dbm + ' dBm (较弱)';
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load: function() {
		return callStatus().catch(function() { return { ok: 0 }; });
	},

	render: function(state) {
		var self = this;
		injectCss();
		this.state = state || {};
		this.scanResults = [];
		this.bandFilter = 'all';
		this.selectedKey = '';
		this.formInitialized = false;

		this.statusBox = E('div', { 'class': 'f50r-card' });
		this.routeBox = E('div', { 'class': 'f50r-card' });
		this.scanListEl = E('div', { 'class': 'f50r-scan-list' }, [
			E('div', { 'class': 'f50r-note' }, '点击上方「扫描周围 Wi-Fi」即可搜索附近 2.4G / 5G 热点，也可以直接在下方手动输入。')
		]);

		this.ssidInput = E('input', { 'class': 'f50r-input', 'type': 'text', 'maxlength': '32', 'placeholder': '输入或从上方列表选择 Wi-Fi 名称' });
		this.bandSelect = E('select', { 'class': 'f50r-select' }, [
			E('option', { 'value': '2g' }, '2.4 GHz'),
			E('option', { 'value': '5g' }, '5 GHz')
		]);
		this.channelInput = E('input', { 'class': 'f50r-input', 'type': 'text', 'placeholder': 'auto（自动）或信道号' });
		this.encSelect = E('select', { 'class': 'f50r-select' }, [
			E('option', { 'value': 'psk2' }, 'WPA2-PSK (最常用)'),
			E('option', { 'value': 'sae-mixed' }, 'WPA2/WPA3 混合'),
			E('option', { 'value': 'sae' }, 'WPA3-SAE'),
			E('option', { 'value': 'psk-mixed' }, 'WPA/WPA2 兼容'),
			E('option', { 'value': 'none' }, '开放（无密码）')
		]);
		this.keyInput = E('input', { 'class': 'f50r-input', 'type': 'password', 'maxlength': '63', 'autocomplete': 'new-password', 'placeholder': '输入 Wi-Fi 密码（同 SSID 留空保持原密码）' });
		this.toggleStaPwBtn = E('button', {
			'class': 'f50r-btn',
			'type': 'button',
			'click': function() {
				var show = self.keyInput.type === 'password';
				self.keyInput.type = show ? 'text' : 'password';
				self.toggleStaPwBtn.textContent = show ? '隐藏' : '显示';
			}
		}, '显示');

		this.encSelect.addEventListener('change', function() {
			var open = self.encSelect.value === 'none';
			self.keyInput.disabled = open;
			if (open) self.keyInput.value = '';
		});

		this.ssidInput.addEventListener('input', function() {
			if (self.selectedKey) {
				self.selectedKey = '';
				if (self.scanResults && self.scanResults.length) self.paintScanList();
			}
		});

		this.scanBtn = E('button', {
			'class': 'f50r-btn primary',
			'type': 'button',
			'click': function() { self.doScan(); }
		}, '扫描周围 Wi-Fi');

		this.connectBtn = E('button', {
			'class': 'f50r-btn primary',
			'type': 'button',
			'click': function() { self.doConnect(); }
		}, '保存并连接中继');

		this.filterBtns = {
			all: E('button', { 'class': 'f50r-btn active', 'type': 'button', 'click': function() { self.setFilter('all'); } }, '全部'),
			'2g': E('button', { 'class': 'f50r-btn', 'type': 'button', 'click': function() { self.setFilter('2g'); } }, '2.4 GHz'),
			'5g': E('button', { 'class': 'f50r-btn', 'type': 'button', 'click': function() { self.setFilter('5g'); } }, '5 GHz')
		};

		var repeaterCard = E('div', { 'class': 'f50r-card' }, [
			E('div', { 'class': 'f50r-head' }, [
				E('div', {}, [
					E('h3', { 'class': 'f50r-title' }, '选择上级 Wi-Fi 进行中继'),
					E('div', { 'class': 'f50r-sub' }, '支持 2.4G / 5G 扫描点选；连接后自动保持本机热点并发广播。')
				]),
				this.scanBtn
			]),
			E('div', { 'class': 'f50r-filters' }, [
				this.filterBtns.all,
				this.filterBtns['2g'],
				this.filterBtns['5g']
			]),
			this.scanListEl,
			E('div', { 'class': 'f50r-form' }, [
				E('div', { 'class': 'f50r-field' }, [
					E('label', { 'class': 'f50r-label' }, '上级 Wi-Fi 名称 (SSID)'),
					this.ssidInput
				]),
				E('div', { 'class': 'f50r-field' }, [
					E('label', { 'class': 'f50r-label' }, '加密方式'),
					this.encSelect
				]),
				E('div', { 'class': 'f50r-field' }, [
					E('label', { 'class': 'f50r-label' }, '频段'),
					this.bandSelect
				]),
				E('div', { 'class': 'f50r-field' }, [
					E('label', { 'class': 'f50r-label' }, '信道（推荐自动或扫描带入）'),
					this.channelInput
				]),
				E('div', { 'class': 'f50r-field full' }, [
					E('label', { 'class': 'f50r-label' }, '上级 Wi-Fi 密码'),
					E('div', { 'class': 'f50r-pw-row' }, [ this.keyInput, this.toggleStaPwBtn ])
				])
			]),
			E('div', { 'class': 'f50r-actions' }, [ this.connectBtn ]),
			E('div', { 'class': 'f50r-note' }, '防失联保护已启用：点击连接后 Wi-Fi 会短暂重启 10~15 秒；如果密码输错或上级热点不可达，约 25 秒后会自动回退并恢复本机热点，手机重连本机热点即可重新修改。')
		]);

		// Local AP quick editor
		this.apSsidInput = E('input', { 'class': 'f50r-input', 'type': 'text', 'maxlength': '32' });
		this.apEncSelect = E('select', { 'class': 'f50r-select' }, [
			E('option', { 'value': 'psk2' }, 'WPA2-PSK (推荐)'),
			E('option', { 'value': 'sae-mixed' }, 'WPA2/WPA3 混合'),
			E('option', { 'value': 'none' }, '开放（无密码）')
		]);
		this.apKeyInput = E('input', { 'class': 'f50r-input', 'type': 'password', 'maxlength': '63', 'autocomplete': 'new-password', 'placeholder': '留空则保持当前热点密码不变' });
		this.toggleApPwBtn = E('button', {
			'class': 'f50r-btn',
			'type': 'button',
			'click': function() {
				var show = self.apKeyInput.type === 'password';
				self.apKeyInput.type = show ? 'text' : 'password';
				self.toggleApPwBtn.textContent = show ? '隐藏' : '显示';
			}
		}, '显示');
		this.apEncSelect.addEventListener('change', function() {
			var open = self.apEncSelect.value === 'none';
			self.apKeyInput.disabled = open;
			if (open) self.apKeyInput.value = '';
		});
		this.apSaveBtn = E('button', {
			'class': 'f50r-btn primary',
			'type': 'button',
			'click': function() { self.doSaveAp(); }
		}, '保存本机热点设置');

		var apCard = E('div', { 'class': 'f50r-card' }, [
			E('div', { 'class': 'f50r-head' }, [
				E('div', {}, [
					E('h3', { 'class': 'f50r-title' }, '本机热点快捷设置'),
					E('div', { 'class': 'f50r-sub' }, '手机/电脑连接此热点访问 http://192.168.77.1 进行管理。')
				])
			]),
			E('div', { 'class': 'f50r-form' }, [
				E('div', { 'class': 'f50r-field' }, [
					E('label', { 'class': 'f50r-label' }, '本机热点名称 (SSID)'),
					this.apSsidInput
				]),
				E('div', { 'class': 'f50r-field' }, [
					E('label', { 'class': 'f50r-label' }, '加密方式'),
					this.apEncSelect
				]),
				E('div', { 'class': 'f50r-field full' }, [
					E('label', { 'class': 'f50r-label' }, '新热点密码（至少 8 位，留空不修改）'),
					E('div', { 'class': 'f50r-pw-row' }, [ this.apKeyInput, this.toggleApPwBtn ])
				])
			]),
			E('div', { 'class': 'f50r-actions' }, [ this.apSaveBtn ])
		]);

		this.paint(this.state);

		poll.add(function() {
			return callStatus().then(function(st) {
				if (st && st.ok === 1) {
					self.state = st;
					self.paint(st);
				}
			}).catch(function() {});
		}, 5);

		return E('div', { 'class': 'f50r-wrap' }, [
			this.statusBox,
			this.routeBox,
			repeaterCard,
			apCard
		]);
	},

	paint: function(st) {
		var self = this;
		var sta = st.sta || {};
		var ap = st.ap || {};
		var wan = st.wan || {};
		var defRt = st.default_route || {};

		if (!this.formInitialized && st.ok === 1) {
			this.formInitialized = true;
			this.ssidInput.value = sta.ssid || '';
			this.bandSelect.value = (st.radio && st.radio.band === '5g') ? '5g' : '2g';
			this.channelInput.value = (st.radio && st.radio.channel) ? st.radio.channel : 'auto';
			this.encSelect.value = sta.encryption || 'psk2';
			this.keyInput.disabled = (this.encSelect.value === 'none');
			this.apSsidInput.value = ap.ssid || 'F50Pro-OpenWrt';
			this.apEncSelect.value = ap.encryption || 'psk2';
			this.apKeyInput.disabled = (this.apEncSelect.value === 'none');
		}

		var badgeCls = 'off', badgeText = '仅本机热点（中继已关闭）';
		if (st.repeater_mode === 'connected') {
			badgeCls = 'ok'; badgeText = 'Wi-Fi 中继已连接';
		} else if (st.repeater_mode === 'connecting') {
			badgeCls = 'warn'; badgeText = '正在连接上级 Wi-Fi…';
		} else if (st.repeater_mode === 'fallback_ap') {
			badgeCls = 'warn'; badgeText = '防失联回退中（仅本机热点）';
		}

		var defLabel = '暂无默认出口';
		if (defRt.dev) {
			if (defRt.dev.indexOf('phy0') === 0 || defRt.dev.indexOf('wlan') === 0)
				defLabel = 'Wi-Fi 中继 (' + defRt.dev + ')';
			else if (defRt.dev.indexOf('sipa') === 0 || defRt.dev.indexOf('wwan') === 0)
				defLabel = '蜂窝流量卡 (' + defRt.dev + ')';
			else
				defLabel = defRt.dev;
		}

		var statusChildren = [
			E('div', { 'class': 'f50r-head' }, [
				E('div', {}, [
					E('h3', { 'class': 'f50r-title' }, 'Wi-Fi 中继实时状态'),
					E('div', { 'class': 'f50r-sub' }, '支持无 SIM 卡纯 Wi-Fi 中继，也可与流量卡自动主备切换。')
				]),
				E('span', { 'class': 'f50r-badge ' + badgeCls }, badgeText)
			]),
			E('div', { 'class': 'f50r-grid3' }, [
				E('div', { 'class': 'f50r-stat' }, [
					E('div', { 'class': 'f50r-stat-k' }, '上行 Wi-Fi 中继'),
					E('div', { 'class': 'f50r-stat-v' }, sta.enabled ? (sta.ssid || '未配置') : '已停用'),
					E('div', { 'class': 'f50r-stat-m' }, sta.connected
						? ('信号 ' + signalDesc(sta.signal) + ' · ' + (sta.band === '5g' ? '5G' : '2.4G') + ' 信道 ' + (sta.channel || '--') + '\nIP: ' + (sta.ip || '获取中…') + (sta.gateway ? (' / 网关 ' + sta.gateway) : ''))
						: (sta.enabled ? '未连接上级热点' : '当前为纯热点模式'))
				]),
				E('div', { 'class': 'f50r-stat' }, [
					E('div', { 'class': 'f50r-stat-k' }, '本机热点 (AP)'),
					E('div', { 'class': 'f50r-stat-v' }, ap.ssid || 'F50Pro-OpenWrt'),
					E('div', { 'class': 'f50r-stat-m' }, ap.active
						? ('广播正常 · ' + (ap.band === '5g' ? '5G' : '2.4G') + ' 信道 ' + (ap.channel || '--') + ' · 已连 ' + (ap.clients || 0) + ' 台设备')
						: '等待拉起中…')
				]),
				E('div', { 'class': 'f50r-stat' }, [
					E('div', { 'class': 'f50r-stat-k' }, '当前上网出口'),
					E('div', { 'class': 'f50r-stat-v' }, defLabel),
					E('div', { 'class': 'f50r-stat-m' }, '蜂窝流量卡：' + (wan.disabled ? '已关闭' : (wan.up ? ('在线 (' + (wan.ip || '--') + ')') : '无卡或未拨号')))
				])
			])
		];

		if (st.repeater_mode === 'fallback_ap') {
			statusChildren.push(E('div', { 'class': 'f50r-banner' },
				'未能连上已保存的「' + (sta.ssid || '') + '」，已自动切回本机热点防止失联。你可以在下方扫描更换其它 Wi-Fi，或检查密码后点「重试连接」。'));
		}

		statusChildren.push(E('div', { 'class': 'f50r-actions' }, [
			E('button', {
				'class': 'f50r-btn',
				'type': 'button',
				'click': function() { self.doRetry(); }
			}, '重新连接已保存 Wi-Fi'),
			E('button', {
				'class': 'f50r-btn danger',
				'type': 'button',
				'click': function() { self.doDisconnect('5g'); }
			}, '关闭中继（恢复 5GHz 纯热点）'),
			E('button', {
				'class': 'f50r-btn',
				'type': 'button',
				'click': function() { self.doDisconnect('2g'); }
			}, '关闭中继（2.4GHz 纯热点）')
		]));

		dom.content(this.statusBox, statusChildren);

		// Route mode switcher
		var rm = st.route_mode || 'cell_first';
		dom.content(this.routeBox, [
			E('div', { 'class': 'f50r-head' }, [
				E('div', {}, [
					E('h3', { 'class': 'f50r-title' }, '上网出口优先级（即时切换，不断 Wi-Fi）'),
					E('div', { 'class': 'f50r-sub' }, '无 SIM 卡时选择任意含 Wi-Fi 中继的选项均可直接上网。')
				])
			]),
			E('div', { 'class': 'f50r-seg' }, [
				E('button', {
					'class': 'f50r-btn' + (rm === 'wifi_first' ? ' active' : ''),
					'type': 'button',
					'click': function() { self.doRouteMode('wifi_first'); }
				}, [
					E('span', {}, 'Wi-Fi 中继优先'),
					E('span', { 'class': 'f50r-seg-sub' }, '插卡时也先走 Wi-Fi，断开自动切流量')
				]),
				E('button', {
					'class': 'f50r-btn' + (rm === 'cell_first' ? ' active' : ''),
					'type': 'button',
					'click': function() { self.doRouteMode('cell_first'); }
				}, [
					E('span', {}, '流量卡优先'),
					E('span', { 'class': 'f50r-seg-sub' }, '无卡或停机时自动走 Wi-Fi 中继')
				]),
				E('button', {
					'class': 'f50r-btn' + (rm === 'wifi_only' ? ' active' : ''),
					'type': 'button',
					'click': function() { self.doRouteMode('wifi_only'); }
				}, [
					E('span', {}, '仅 Wi-Fi 中继'),
					E('span', { 'class': 'f50r-seg-sub' }, '彻底停用蜂窝流量卡（零流量消耗）')
				])
			])
		]);
	},

	setFilter: function(f) {
		this.bandFilter = f;
		Object.keys(this.filterBtns).forEach(function(k) {
			this.filterBtns[k].classList.toggle('active', k === f);
		}, this);
		this.paintScanList();
	},

	paintScanList: function() {
		var self = this;
		var list = (this.scanResults || []).filter(function(r) {
			return self.bandFilter === 'all' || r.band === self.bandFilter;
		});
		if (!list.length) {
			dom.content(this.scanListEl, E('div', { 'class': 'f50r-note' }, '当前筛选下没有扫描到 Wi-Fi，请点击「扫描周围 Wi-Fi」重试或切换频段筛选。'));
			return;
		}
		var curSta = (this.state && this.state.sta) || {};
		dom.content(this.scanListEl, list.map(function(item) {
			var k = item.ssid + '|' + item.band;
			var isCur = !!(curSta.connected && curSta.ssid === item.ssid && curSta.band === item.band);
			var meta = [
				E('span', { 'class': 'f50r-tag' + (item.band === '5g' ? ' b5' : '') }, item.band === '5g' ? '5 GHz' : '2.4 GHz'),
				E('span', {}, '信道 ' + (item.channel || '--')),
				E('span', {}, item.enc_label || item.encryption),
				E('span', {}, signalDesc(item.signal))
			];
			if (isCur) meta.unshift(E('span', { 'class': 'f50r-tag b5' }, '当前已连'));
			return E('div', {
				'class': 'f50r-scan-row' + (self.selectedKey === k ? ' selected' : ''),
				'click': function() {
					self.selectedKey = k;
					self.ssidInput.value = item.ssid;
					self.bandSelect.value = item.band;
					self.channelInput.value = item.channel ? String(item.channel) : 'auto';
					self.encSelect.value = item.encryption || 'psk2';
					var open = self.encSelect.value === 'none';
					self.keyInput.disabled = open;
					if (open) self.keyInput.value = '';
					else self.keyInput.focus();
					self.paintScanList();
				}
			}, [
				E('div', { 'class': 'f50r-scan-main' }, [
					E('div', { 'class': 'f50r-scan-ssid' }, item.ssid),
					E('div', { 'class': 'f50r-scan-meta' }, meta)
				]),
				E('button', { 'class': 'f50r-btn', 'type': 'button' }, self.selectedKey === k ? '已选' : '选择')
			]);
		}));
	},

	doScan: function() {
		var self = this;
		this.scanBtn.disabled = true;
		this.scanBtn.textContent = '扫描中…';
		dom.content(this.scanListEl, E('div', { 'class': 'f50r-note' }, '正在扫描周围 2.4G / 5G Wi-Fi（约 2~4 秒）…'));
		return callScan().then(function(res) {
			if (!res || res.ok === 0) {
				var errMsg = (res && res.error) ? res.error : '无线接口暂时无法扫描，请稍候重试';
				self.scanResults = [];
				dom.content(self.scanListEl, E('div', { 'class': 'f50r-note' }, '扫描失败：' + errMsg));
				return;
			}
			self.scanResults = (res && res.results) || [];
			self.paintScanList();
		}).catch(function() {
			dom.content(self.scanListEl, E('div', { 'class': 'f50r-note' }, '扫描请求失败，请确认与路由器连接正常后重试。'));
		}).finally(function() {
			self.scanBtn.disabled = false;
			self.scanBtn.textContent = '扫描周围 Wi-Fi';
		});
	},

	doConnect: function() {
		var self = this;
		var ssid = String(this.ssidInput.value || '');
		var enc = this.encSelect.value || 'psk2';
		var key = this.keyInput.value || '';
		var band = this.bandSelect.value || '2g';
		var ch = (this.channelInput.value || 'auto').trim() || 'auto';

		if (!ssid || ssid.length === 0) {
			ui.addNotification(null, E('p', '请先选择或输入上级 Wi-Fi 名称'), 'warning');
			return;
		}
		if (enc !== 'none' && key.length > 0 && key.length < 8) {
			ui.addNotification(null, E('p', 'Wi-Fi 密码至少需要 8 位'), 'warning');
			return;
		}

		this.connectBtn.disabled = true;
		this.connectBtn.textContent = '正在应用…';
		return callConnect(ssid, key, enc, band, ch).then(function(r) {
			if (!r || r.ok !== 1) {
				ui.addNotification(null, E('p', '保存失败：' + (r && r.error || '未知错误')), 'danger');
				return;
			}
			self.keyInput.value = '';
			ui.addNotification(null, E('p', '已保存「' + ssid + '」并开始中继连接。Wi-Fi 将短暂重启 10~15 秒，请稍候刷新（若无法连接，约 25 秒后会自动恢复本机热点）。'), 'info');
		}).catch(function() {
			ui.addNotification(null, E('p', '已发送连接指令，无线正在重启中，请 15 秒后重连本机热点查看状态。'), 'info');
		}).finally(function() {
			self.connectBtn.disabled = false;
			self.connectBtn.textContent = '保存并连接中继';
		});
	},

	doDisconnect: function(apBand) {
		return callDisconnect(apBand).then(function(r) {
			if (!r || r.ok !== 1) {
				ui.addNotification(null, E('p', '操作失败：' + (r && r.error || '未知错误')), 'danger');
				return;
			}
			ui.addNotification(null, E('p', '已关闭 Wi-Fi 中继，正在切换为 ' + (apBand === '5g' ? '5 GHz' : '2.4 GHz') + ' 纯热点模式（约 10 秒后生效）。'), 'info');
		}).catch(function() {
			ui.addNotification(null, E('p', '指令已下发，热点重启中，请稍候重连。'), 'info');
		});
	},

	doRouteMode: function(mode) {
		var self = this;
		return callRouteMode(mode).then(function(r) {
			if (!r || r.ok !== 1) {
				ui.addNotification(null, E('p', '切换失败：' + (r && r.error || '未知错误')), 'danger');
				return;
			}
			ui.addNotification(null, E('p', '上网出口优先级已切换生效'), 'info');
			return callStatus().then(function(st) {
				if (st && st.ok === 1) { self.state = st; self.paint(st); }
			});
		}).catch(function() {
			ui.addNotification(null, E('p', '切换请求失败，请重试'), 'danger');
		});
	},

	doSaveAp: function() {
		var self = this;
		var ssid = (this.apSsidInput.value || '').trim();
		var enc = this.apEncSelect.value || 'psk2';
		var key = this.apKeyInput.value || '';

		if (!ssid) {
			ui.addNotification(null, E('p', '本机热点名称不能为空'), 'warning');
			return;
		}
		if (enc !== 'none' && key.length > 0 && key.length < 8) {
			ui.addNotification(null, E('p', '热点密码至少需要 8 位'), 'warning');
			return;
		}

		this.apSaveBtn.disabled = true;
		return callApConfig(ssid, key, enc).then(function(r) {
			if (!r || r.ok !== 1) {
				ui.addNotification(null, E('p', '保存失败：' + (r && r.error || '未知错误')), 'danger');
				return;
			}
			self.apKeyInput.value = '';
			ui.addNotification(null, E('p', '本机热点配置已保存，热点将短暂重启，请使用新热点名/密码重新连接。'), 'info');
		}).catch(function() {
			ui.addNotification(null, E('p', '本机热点正在重启生效。'), 'info');
		}).finally(function() {
			self.apSaveBtn.disabled = false;
		});
	},

	doRetry: function() {
		return callRetry().then(function(r) {
			if (!r || r.ok !== 1) {
				ui.addNotification(null, E('p', '重试失败：' + (r && r.error || '请先配置上级 Wi-Fi')), 'warning');
				return;
			}
			ui.addNotification(null, E('p', '正在重新连接已保存的上级 Wi-Fi（约 10~15 秒）…'), 'info');
		}).catch(function() {
			ui.addNotification(null, E('p', '重连指令已下发，请稍候。'), 'info');
		});
	}
});
