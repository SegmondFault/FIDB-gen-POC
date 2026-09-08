export type BatchRow = {
  id: string;
  name: string;
  status: 'Defined' | 'Running' | 'Blocked' | 'Complete' | 'Queued';
  progress: string;
  percent: number;
  worker: string;
  route: string;
  eta: string;
  tier?: string;
  note?: string;
};
