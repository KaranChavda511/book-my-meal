export interface IRestaurant {
  id: string;
  name: string;
  address: string;
  phone: string;
  ownerId: string; // userId of restaurant owner
  createdAt?: Date;
  updatedAt?: Date;
}
