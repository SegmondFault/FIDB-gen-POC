export async function settlePanelRead(key, read) {
  try {
    return { key, value: await read(), error: null };
  } catch (caught) {
    return {
      key,
      value: null,
      error: caught instanceof Error ? caught.message : 'Panel data unavailable',
    };
  }
}
