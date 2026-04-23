// Tiny Web Audio API helper for the SoundService. Synthesizes short tones so we
// don't need to ship copyrighted Windows XP sound files.
(function () {
    let ctx = null;
    function ensureCtx() {
        if (ctx) return ctx;
        try {
            const C = window.AudioContext || window.webkitAudioContext;
            if (!C) return null;
            ctx = new C();
            return ctx;
        } catch { return null; }
    }

    window.xpSound = {
        play: function (freqs, duration, volume) {
            const c = ensureCtx();
            if (!c) return;
            const now = c.currentTime;
            const gain = c.createGain();
            gain.gain.value = 0;
            gain.gain.linearRampToValueAtTime(volume, now + 0.005);
            gain.gain.linearRampToValueAtTime(0, now + duration);
            gain.connect(c.destination);
            (freqs || []).forEach(f => {
                const o = c.createOscillator();
                o.type = 'triangle';
                o.frequency.value = f;
                o.connect(gain);
                o.start(now);
                o.stop(now + duration + 0.05);
            });
        }
    };
})();
