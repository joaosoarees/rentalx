import { Category } from '../model/Category';
import {
  ICategoriesRepository,
  ICreateCategoryDTO,
} from './ICategoriesRepository';

export class PostgresCategoriesRepository implements ICategoriesRepository {
  create({ name, description }: ICreateCategoryDTO): void {
    console.log({ name, description });
  }
  findByName(name: string): Category {
    console.log(name);

    return null;
  }
  list(): Category[] {
    console.log('list');

    return null;
  }
}
