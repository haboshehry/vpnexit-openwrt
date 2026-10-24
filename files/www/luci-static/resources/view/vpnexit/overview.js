'use strict';
'require view';
'require poll';

return view.extend({
	load: function () {
		return null;
	},

	render: function () {
		var toolbar = E('div', { 'class': 'cbi-page-actions', 'style': 'margin-bottom:8px' }, [
			E('a', {
				'class': 'btn cbi-button cbi-button-apply',
				'href': '/vpnexit/',
				'target': '_blank',
				'rel': 'noopener'
			}, _('Open panel in a new tab')),
			' ',
			E('a', {
				'class': 'btn cbi-button',
				'href': '/vpnexit/source.txt',
				'target': '_blank',
				'rel': 'noopener'
			}, _('Backend source'))
		]);

		var frame = E('iframe', {
			'src': '/vpnexit/',
			'style': 'width:100%;height:78vh;border:1px solid var(--border-color-medium,rgba(0,0,0,.15));border-radius:8px;background:#0a0e14',
			'title': 'VPN Exit'
		});

		return E('div', {}, [
			E('h2', {}, _('VPN Exit')),
			E('div', { 'class': 'cbi-section-descr', 'style': 'margin-bottom:10px' }, _(
				'Pick an exit location here; every wired and Wi-Fi client of this router will use it. ' +
				'If the frame stays empty, open the panel in a new tab.'
			)),
			toolbar,
			frame
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
