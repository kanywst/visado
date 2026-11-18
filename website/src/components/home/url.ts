/** Prefix a site path with the configured base, e.g. url('/roadmap/') -> '/visado/roadmap/'. */
export const url = (path: string) => `${import.meta.env.BASE_URL.replace(/\/$/, '')}${path}`;
