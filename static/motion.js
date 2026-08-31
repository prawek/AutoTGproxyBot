/* GSAP owns the hero entrance. Content remains readable when animation is unavailable. */
window.ProxyMotion = {
  media: null,
  feedbackTween: null,
  enter(root) {
    this.clear();
    if (!root || !window.gsap) return;
    const hero = root.querySelector('[data-enter]');
    if (!hero) return;
    this.media = gsap.matchMedia();
    this.media.add('(prefers-reduced-motion: no-preference)', () => {
      const timeline = gsap.timeline({defaults: {duration: .8, ease: 'power3.out'}});
      timeline.from(hero.querySelectorAll('.home-title > span'),
        {y: 24, opacity: .5, stagger: .1, clearProps: 'transform,opacity'})
        .from(hero.querySelector('.home-intro'), {y: 12, opacity: .6, clearProps: 'transform,opacity'}, .2)
        .from(hero.querySelector('.home-connect'), {y: 20, opacity: .65, clearProps: 'transform,opacity'}, .25)
        .from(hero.querySelectorAll('.home-path-line'), {scaleX: 0, transformOrigin: 'left center', stagger: .1, clearProps: 'transform'}, .6);
    }, root);
  },
  feedback(root) {
    this.feedbackTween?.kill();
    if (!root || !window.gsap || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    this.feedbackTween = gsap.fromTo(root, {y: 6, opacity: .65}, {y: 0, opacity: 1, duration: .25, ease: 'power2.out', overwrite: 'auto', clearProps: 'transform,opacity'});
  },
  clear() {
    this.feedbackTween?.kill();
    this.feedbackTween = null;
    this.media?.revert();
    this.media = null;
  },
};
