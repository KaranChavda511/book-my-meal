export interface IMenuItem {
  id: string;
  restaurantId: string;
  name: string;
  description?: string;
  price: number;
  available: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}
