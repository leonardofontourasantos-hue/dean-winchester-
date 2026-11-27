let isNavigating = false

window.navigateWithTransition = (url) => {
  if (isNavigating) return
  isNavigating = true

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    window.location.href = url
    return
  }

  document.body.classList.add('page-exit')
  window.setTimeout(() => {
    window.location.href = url
  }, 300) }