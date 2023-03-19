import adapter from '@sveltejs/adapter-static';
import preprocess from 'svelte-preprocess';
 
export default {
  preprocess: preprocess(),
  kit: {
    adapter: adapter({
      pages: '../internal/server/htdocs',
      assets: '../internal/server/htdocs',
      fallback: null,
      precompress: false,
      strict: true
    })
  }
};