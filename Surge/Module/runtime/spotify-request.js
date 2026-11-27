(() => {
  const url=$request.url;
  if(!/^https:\/\/(?:spclient\.wg|[a-z0-9-]+-spclient(?:\.wg)?)\.spotify\.com(?::443)?\/(?:artistview\/v1\/artist|album-entity-view\/v2\/album)\//i.test(url)){ $done({}); return; }
  const next=url.replace(/(\?|&)platform=iphone(?=&|$)/,'$1platform=ipad');
  $done(next===url?{}:{url:next});
})();
