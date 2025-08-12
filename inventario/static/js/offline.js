// Basic offline detection UI hook
window.addEventListener('load', ()=>{
  function update(){
    const online = navigator.onLine;
    document.body.classList.toggle('offline', !online);
  }
  window.addEventListener('online', update);
  window.addEventListener('offline', update);
  update();
});
